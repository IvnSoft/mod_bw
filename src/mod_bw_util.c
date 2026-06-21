/*
 * mod_bw_util.c - Statistics helpers: CSV export, bandwidth estimation,
 *                 hourly rollover, and the legacy HTML status page.
 */

#include "mod_bw.h"
#include "mod_bw_config.h"
#include "mod_bw_shm.h"
#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_time.h>

/* ------------------------------------------------------------------ */
/* bw_save_csv - write all vhost metrics to a dated CSV file          */
/* ------------------------------------------------------------------ */
void bw_save_csv(apr_pool_t *p, int clear_hourly)
{
  if (!bw_g.hdr || !bw_g.vhosts)
    return;

  apr_time_exp_t te;
  apr_time_exp_tz(&te, apr_time_now(), 0);

  char path[512];
  apr_snprintf(path, sizeof(path), "%s/%04d-%02d-%02d.csv",
               bw_g.stats_dir ? bw_g.stats_dir : STATS_DIR_DEFAULT,
               te.tm_year + 1900, te.tm_mon + 1, te.tm_mday);

  apr_file_t *fp = NULL;
  apr_file_open(&fp, path,
                APR_WRITE | APR_CREATE | APR_APPEND,
                APR_OS_DEFAULT, p);
  if (!fp)
    return;

  apr_uint32_t i, h;
  for (i = 0; i < bw_g.hdr->max_vhosts; i++)
  {
    bw_vhost_slot_t *v = &bw_g.vhosts[i];
    if (apr_atomic_read32(&v->flags) != BW_SLOT_ACTIVE)
      continue;

    apr_uint32_t bw_out = bw_ring_sum(&v->stats.ring_out,
                                      (apr_uint32_t)(apr_time_now() / APR_USEC_PER_SEC),
                                      5);
    apr_uint64_t bytes_out = bw_bytes64_read(&v->stats.bytes_out);
    apr_uint64_t bytes_in = bw_bytes64_read(&v->stats.bytes_in);

    char line[4096];
    apr_snprintf(line, sizeof(line),
                 "%u,%s,%u,%u,%" APR_UINT64_T_FMT ",%" APR_UINT64_T_FMT ",%u,%u,%u,",
                 v->id, v->name,
                 v->stats.connection_count,
                 bw_out, bytes_out, bytes_in,
                 v->stats.counter,
                 v->stats.throttled,
                 v->stats.cutoff);

    apr_size_t len = strlen(line);
    apr_file_write(fp, line, &len);

    for (h = 0; h < 24; h++)
    {
      apr_snprintf(line, sizeof(line), "%u,", v->stats.conn_avg[h]);
      len = strlen(line);
      apr_file_write(fp, line, &len);
      if (clear_hourly)
        apr_atomic_set32(&v->stats.conn_avg[h], 0);
    }
    for (h = 0; h < 24; h++)
    {
      apr_snprintf(line, sizeof(line), "%u,", v->stats.counter_avg[h]);
      len = strlen(line);
      apr_file_write(fp, line, &len);
      if (clear_hourly)
        apr_atomic_set32(&v->stats.counter_avg[h], 0);
    }

    const char *end = "END\n";
    len = strlen(end);
    apr_file_write(fp, end, &len);
  }

  apr_file_close(fp);
}

/* ------------------------------------------------------------------ */
/* bw_check_rollover - called from handle_bw once per request         */
/* Triggers CSV export on hourly/daily boundary.                      */
/* ------------------------------------------------------------------ */
void bw_check_rollover(apr_pool_t *p)
{
  if (!bw_g.hdr)
    return;

  apr_time_exp_t te;
  apr_time_exp_tz(&te, apr_time_now(), 0);

  apr_uint32_t now_yday = (apr_uint32_t)te.tm_yday;
  apr_uint32_t now_hour = (apr_uint32_t)te.tm_hour;
  apr_uint32_t now_min = (apr_uint32_t)te.tm_min;

  apr_uint32_t last_yday = apr_atomic_read32(&bw_g.hdr->last_yday);
  apr_uint32_t last_min = apr_atomic_read32(&bw_g.hdr->last_min);
  apr_uint32_t last_hour = apr_atomic_read32(&bw_g.hdr->last_hour);

  /* Write CSV every 60 seconds; clear hourly arrays on day rollover */
  apr_uint32_t elapsed = (now_yday * 86400u + now_hour * 3600u + now_min * 60u) - (last_yday * 86400u + last_hour * 3600u + last_min * 60u);

  if (elapsed < 60u)
    return;

  /* Only one worker should do this: CAS on last_min */
  if (apr_atomic_cas32(&bw_g.hdr->last_min, now_min, last_min) != last_min)
    return; /* another worker beat us */

  apr_atomic_set32(&bw_g.hdr->last_hour, now_hour);
  apr_atomic_set32(&bw_g.hdr->last_yday, now_yday);

  int clear = (now_yday != last_yday);
  bw_save_csv(p, clear);
}

/* ------------------------------------------------------------------ */
/* bw_status_handler - HTML status page (handler "mod-bw-status")     */
/* ------------------------------------------------------------------ */
int bw_status_handler(request_rec *r)
{
  if (strcmp(r->handler, "mod-bw-status") != 0)
    return DECLINED;

  ap_set_content_type(r, "text/html;charset=utf-8");
  if (r->header_only)
    return OK;

  ap_rputs("<!DOCTYPE html><html><head>"
           "<title>mod_bw status</title>"
           "<style>body{font-family:monospace;font-size:13px}"
           "table{border-collapse:collapse}td,th{border:1px solid #ccc;"
           "padding:4px 8px}th{background:#eee}</style>"
           "</head><body>",
           r);

  ap_rprintf(r, "<h2>mod_bw %s - %s</h2>", MOD_BW_VERSION,
             ap_get_server_description());

  if (bw_g.mod_disabled || !bw_g.hdr)
  {
    ap_rputs("<p><b>Module globally disabled or not initialised.</b></p>", r);
    ap_rputs("</body></html>", r);
    return OK;
  }

  apr_uint32_t now_sec =
      (apr_uint32_t)(apr_time_now() / APR_USEC_PER_SEC);

  ap_rprintf(r,
             "<p>SHM: <code>%s</code> &nbsp; "
             "Slots: %u/%u vhosts &nbsp; %u/%u pools &nbsp; %u/%u rules</p>",
             ap_escape_html(r->pool, bw_g.hdr->shm_file),
             bw_g.hdr->n_vhosts, bw_g.hdr->max_vhosts,
             bw_g.hdr->n_pools, bw_g.hdr->max_pools,
             bw_g.hdr->n_rules, bw_g.hdr->max_rules);

  apr_uint32_t i;
  for (i = 0; i < bw_g.hdr->max_vhosts; i++)
  {
    bw_vhost_slot_t *v = &bw_g.vhosts[i];
    if (apr_atomic_read32(&v->flags) != BW_SLOT_ACTIVE)
      continue;

    apr_uint32_t bw_out = bw_ring_sum(&v->stats.ring_out, now_sec, 5);
    apr_uint32_t bw_in = bw_ring_sum(&v->stats.ring_in, now_sec, 5);
    apr_uint64_t bout = bw_bytes64_read(&v->stats.bytes_out);
    apr_uint64_t bin = bw_bytes64_read(&v->stats.bytes_in);

    ap_rprintf(r,
               "<hr><h3>[%u] %s</h3>"
               "<table><tr><th>Metric</th><th>Value</th></tr>"
               "<tr><td>Active connections</td><td>%u</td></tr>"
               "<tr><td>Bandwidth out (5s avg)</td><td>%u bytes/s</td></tr>"
               "<tr><td>Bandwidth in  (5s avg)</td><td>%u bytes/s</td></tr>"
               "<tr><td>Total bytes out</td><td>%" APR_UINT64_T_FMT "</td></tr>"
               "<tr><td>Total bytes in</td><td>%" APR_UINT64_T_FMT "</td></tr>"
               "<tr><td>Requests</td><td>%u</td></tr>"
               "<tr><td>Throttled</td><td>%u</td></tr>"
               "<tr><td>Cutoff (maxconn)</td><td>%u</td></tr>"
               "</table>",
               v->id, ap_escape_html(r->pool, v->name),
               v->stats.connection_count,
               bw_out, bw_in, bout, bin,
               v->stats.counter, v->stats.throttled, v->stats.cutoff);

    /* Pool sub-table */
    ap_rputs("<h4>Pools</h4>"
             "<table><tr><th>idx</th><th>id</th><th>bwlimit</th>"
             "<th>in_bwlimit</th><th>maxc</th><th>active</th>"
             "<th>out bytes/s</th><th>in bytes/s</th></tr>",
             r);

    apr_uint32_t pidx = apr_atomic_read32(&v->pool_root_idx);
    while (pidx != BW_IDX_NONE)
    {
      bw_pool_slot_t *pool = &bw_g.pools[pidx];
      if (apr_atomic_read32(&pool->flags) == BW_SLOT_ACTIVE)
      {
        apr_uint32_t pout = bw_ring_sum(&pool->stats.ring_out, now_sec, 5);
        apr_uint32_t pin = bw_ring_sum(&pool->stats.ring_in, now_sec, 5);
        ap_rprintf(r,
                   "<tr><td>%u</td><td>%u</td><td>%u</td><td>%u</td>"
                   "<td>%u</td><td>%u</td><td>%u</td><td>%u</td></tr>",
                   pidx, pool->id, pool->bwlimit, pool->in_bwlimit,
                   pool->maxc, pool->stats.connection_count, pout, pin);
      }
      pidx = apr_atomic_read32(&pool->next_sibling_idx);
    }
    ap_rputs("</table>", r);
  }

  ap_rputs("</body></html>", r);
  return OK;
}
