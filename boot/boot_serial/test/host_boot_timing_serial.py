#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host regressions for MCUboot boot timing and serial recovery deadlines."""

import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
CC = os.environ.get("CC", "gcc")


def function(source, name):
    """Extract an actual C function definition, retaining preprocessor arms."""
    match = re.search(r"\n" + name + r"\([^;]*?\n\{", source)
    if not match:
        raise AssertionError(f"function not found: {name}")
    start = match.start() + 1
    opening = source.index("{", start)
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"',
                    lambda m: " " * len(m.group()), source, flags=re.S)
    depth = 1
    end = opening + 1
    while depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    return source[start:end]


def compile_run(source, defines=(), include=(), expect_link=True):
    with tempfile.TemporaryDirectory(prefix="mcuboot-timing-") as tmp:
        cfile = Path(tmp) / "test.c"
        binary = Path(tmp) / "test"
        cfile.write_text(source)
        command = [CC, "-std=c11", "-Wall", "-Wextra", "-Werror",
                   *defines, *(f"-I{path}" for path in include),
                   str(cfile), "-o", str(binary)]
        result = subprocess.run(command, text=True, capture_output=True)
        if expect_link:
            if result.returncode:
                raise AssertionError(result.stderr)
            subprocess.run([str(binary)], check=True)
        elif result.returncode == 0:
            raise AssertionError("expected missing timing recorder to fail link")
        elif "n6_boot_timing_record" not in result.stderr:
            raise AssertionError("link failure did not identify the missing recorder")


def test_timing_header():
    header = ROOT / "boot/bootutil/include/bootutil/boot_timing.h"
    disabled = f'''#include "{header}"
static int effects;
int main(void) {{
    N6_BOOT_TIME_BEGIN((effects++, unused_start));
    N6_BOOT_TIME_END((effects++, "ignored"), (effects++, 1),
                     (effects++, 2), (effects++, 3), (effects++, 4));
    N6_BOOT_TIME_DUMP();
    return effects;
}}
'''
    compile_run(disabled)

    with tempfile.TemporaryDirectory(prefix="mcuboot-fake-zephyr-") as tmp:
        fake = Path(tmp)
        (fake / "zephyr").mkdir()
        (fake / "zephyr/kernel.h").write_text(
            "#include <stdint.h>\nint64_t k_uptime_get(void);\n")
        enabled = f'''#include <assert.h>
#include <stdint.h>
#include "{header}"
static int64_t clock_ms = 321;
static int calls, dumps, got_area, got_result;
static uint32_t got_bytes;
static int64_t got_start;
static const char *got_phase;
int64_t k_uptime_get(void) {{ return clock_ms; }}
void n6_boot_timing_record(const char *phase, int area, uint32_t bytes,
                           int64_t start_ms, int result) {{
    ++calls; got_phase=phase; got_area=area; got_bytes=bytes;
    got_start=start_ms; got_result=result;
}}
void n6_boot_timing_dump(void) {{ ++dumps; }}
int main(void) {{
    N6_BOOT_TIME_BEGIN(started);
    clock_ms = 456;
    N6_BOOT_TIME_END("payload", 7, 8192, started, -3);
    N6_BOOT_TIME_DUMP();
    assert(calls==1 && dumps==1 && got_phase[0]=='p' && got_area==7);
    assert(got_bytes==8192 && got_start==321 && got_result==-3);
    return 0;
}}
'''
        compile_run(enabled, ("-DCONFIG_N6_BOOT_TIMING",), (fake,))
        compile_run(enabled.replace("void n6_boot_timing_record(",
                                   "void n6_boot_timing_record_missing("),
                    ("-DCONFIG_N6_BOOT_TIMING",), (fake,), expect_link=False)


SERIAL_SOURCE = (ROOT / "boot/boot_serial/src/boot_serial.c").read_text()
SERIAL_PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#define MCUBOOT_SERIAL_RAW_PROTOCOL
#define MCUBOOT_SERIAL_RAW_PROTOCOL_INPUT_TIMEOUT
#define MCUBOOT_SERIAL_RAW_PROTOCOL_INPUT_TIMEOUT_MS 5
#define MCUBOOT_SERIAL_WAIT_FOR_DFU
#define MCUBOOT_SERIAL_INACTIVITY_TIMEOUT
#define NMGR_OP_READ 0
#define NMGR_OP_WRITE 2
#define MCUBOOT_WATCHDOG_FEED() do { fake_ms += loop_overhead_ms; } while (0)
struct nmgr_hdr { uint8_t nh_op; uint8_t nh_flags; uint16_t nh_len; };
struct boot_uart_funcs {
    int (*read)(char *buffer, int size, int *full_line);
};
static char in_buf[64];
static const struct boot_uart_funcs *boot_uf;
static bool bs_entry;
static int bs_rearm_ms;
static bool bs_rearm_pending;
static bool bs_rearm_seen;
static int64_t fake_ms;
static uint32_t raw_clock;
static int loop_overhead_ms;
static int packet_count;
static int64_t read_step_ms;
static int reads, last_packets[8];
static bool add_overhead;
static char stream_data[32];
static int stream_len, stream_off, chunk_count, chunk_index;
static int chunks[8];
static uint32_t os_uptime_get_ms_32(void) { return raw_clock; }
static uint32_t k_uptime_get_32(void) { return (uint32_t)fake_ms; }
static int64_t k_uptime_get(void) { return fake_ms; }
static int boot_serial_input_raw(char *buf, int len, int max_input);
static void boot_serial_input(const char *packet, int len)
{
    const struct nmgr_hdr *hdr=(const struct nmgr_hdr *)packet;
    assert(len == (int)sizeof(*hdr) + ntohs(hdr->nh_len));
    last_packets[packet_count++] = len;
    if (bs_rearm_ms > 0) {
        bs_rearm_pending=true;
        bs_rearm_seen=true;
    }
    if (add_overhead) fake_ms += 2;
}
static int fake_read(char *buf, int size, int *full_line)
{
    ++reads;
    assert(reads <= 1000); /* Keep a broken deadline regression bounded. */
    fake_ms += read_step_ms;
    raw_clock += (uint32_t)read_step_ms;
    *full_line=0;
    if (chunk_index < chunk_count) {
        int n=chunks[chunk_index++];
        assert(n <= size && stream_off+n <= stream_len);
        if (n > 0) {
            memcpy(buf,stream_data+stream_off,(size_t)n);
            stream_off += n;
            *full_line=1;
        }
        return n;
    }
    return 0;
}
static struct boot_uart_funcs funcs={fake_read};
static int make_packet(char *out, uint8_t marker)
{
    struct nmgr_hdr hdr={NMGR_OP_WRITE,0,htons(2)};
    memcpy(out,&hdr,sizeof(hdr)); out[sizeof(hdr)]=marker; out[sizeof(hdr)+1]=marker;
    return sizeof(hdr)+2;
}
static void schedule(const int *sizes,int count,const char *data,int len)
{
    assert(count <= 8 && len <= (int)sizeof(stream_data));
    memcpy(chunks,sizes,(size_t)count*sizeof(sizes[0]));
    memcpy(stream_data,data,(size_t)len);
    chunk_count=count; chunk_index=0; stream_len=len; stream_off=0;
}
'''


def test_serial_loop():
    raw = function(SERIAL_SOURCE, "boot_serial_input_raw")
    loop = function(SERIAL_SOURCE, "boot_serial_read_console")
    harness = r'''
static void reset(void)
{
    memset(in_buf,0,sizeof(in_buf)); packet_count=reads=0;
    memset(last_packets,0,sizeof(last_packets)); bs_entry=false;
    bs_rearm_ms=0; bs_rearm_pending=bs_rearm_seen=false;
    raw_clock=0; read_step_ms=1; chunk_count=chunk_index=0;
    stream_len=stream_off=0;
    fake_ms=0; loop_overhead_ms=0; add_overhead=false;
}
int main(void)
{
    (void)k_uptime_get();
    (void)k_uptime_get_32();
    reset(); fake_ms=(int64_t)UINT32_MAX-1; read_step_ms=1;
    boot_serial_read_console(&funcs,3);
    assert(reads==3); /* deadline crosses the 32-bit uptime wrap */

    reset(); read_step_ms=0; loop_overhead_ms=1;
    boot_serial_read_console(&funcs,3);
    assert(reads==3); /* empty reads still charge whole-loop overhead */

    reset(); read_step_ms=1;
    boot_serial_read_console(&funcs,0);
    assert(reads==0);
    reset(); read_step_ms=1;
    boot_serial_read_console(&funcs,1);
    assert(reads==1); /* a read ending at the deadline counts */

    reset(); fake_ms=INT64_C(5000000000); read_step_ms=INT32_MAX;
    boot_serial_read_console(&funcs,INT32_MAX);
    assert(reads==1); /* one slow empty read can expire the full interval */

#if defined(CONFIG_SOC_SERIES_STM32N6X)
    reset(); read_step_ms=INT64_C(5000000000);
    boot_serial_read_console(&funcs,INT32_MAX);
    assert(reads==1); /* the N6 deadline handles one gap greater than UINT32_MAX */
#endif

    reset(); read_step_ms=1; add_overhead=true;
    char packet[6]; int packet_len=make_packet(packet,'a');
    int rearm_chunks[]={packet_len}; schedule(rearm_chunks,1,packet,packet_len);
    bs_rearm_ms=4;
    boot_serial_read_console(&funcs,2);
    assert(packet_count==1 && bs_rearm_seen && reads==5);
    /* The raw packet re-arms at command completion; its full silence window is counted. */

    reset(); read_step_ms=1; packet_len=make_packet(packet,'b');
    int fragment_chunks[]={2,packet_len-2}; schedule(fragment_chunks,2,packet,packet_len);
    boot_serial_read_console(&funcs,20);
    assert(packet_count==1 && reads==20);
    assert(last_packets[0]==6);

    reset(); read_step_ms=1;
    char pair[12]; make_packet(pair,'c'); make_packet(pair+6,'d');
    int concat_chunks[]={12}; schedule(concat_chunks,1,pair,sizeof(pair));
    boot_serial_read_console(&funcs,20);
    assert(packet_count==2 && reads==20 && last_packets[0]==6 && last_packets[1]==6);

    reset(); read_step_ms=1;
    packet_len=make_packet(packet,'e');
    int partial_chunks[]={2,0,0,0,0,0,packet_len-2};
    schedule(partial_chunks,7,packet,packet_len);
    boot_serial_read_console(&funcs,20);
    assert(packet_count==0 && reads==20);
    puts("PASS: extracted serial loop deadline, wrap, inactivity rearm, raw framing and timeout cases");
}
'''
    source = SERIAL_PRELUDE + "\nstatic int " + raw + "\nstatic void " + loop + "\n" + harness
    for n6 in (False, True):
        definitions = ("-DCONFIG_SOC_SERIES_STM32N6X",) if n6 else ()
        compile_run(source, definitions)


if __name__ == "__main__":
    test_timing_header()
    test_serial_loop()
