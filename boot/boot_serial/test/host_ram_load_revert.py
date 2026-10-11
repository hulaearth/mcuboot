#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 The MCUboot Contributors
"""Compile actual serial state handlers with host flash/CBOR fixtures.

Run with python3 boot/boot_serial/test/host_ram_load_revert.py.
Crypto validation and transport are stubbed; simulator tests cover crypto.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]


def function(source, name, occurrence=0):
    """Extract a definition, retaining its preprocessor branches."""
    matches = list(re.finditer(r"\n" + name + r"\([^;]*?\n\{", source))
    start = matches[occurrence].start() + 1
    opening = source.index("{", start)
    # Mask strings and comments without changing character positions.
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"',
                    lambda match: " " * len(match.group()), source, flags=re.S)
    depth = 1
    end = opening + 1
    while depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    return source[start:end]


serial = (ROOT / "boot/boot_serial/src/boot_serial.c").read_text()
public = (ROOT / "boot/bootutil/src/bootutil_public.c").read_text()
PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define MCUBOOT_RAM_LOAD
#define MCUBOOT_RAM_LOAD_REVERT
#define MCUBOOT_SERIAL_IMG_GRP_HASH
#define MCUBOOT_SERIAL_IMG_GRP_IMAGE_STATE
#define BOOT_IMAGE_NUMBER 1
#define BOOT_NUM_SLOTS 2
#define BOOT_SLOT_SECONDARY 1
#define IMAGE_HASH_SIZE 32
#define IMAGE_MAGIC 0x96f3b83d
#define BOOT_MAGIC_GOOD 1
#define BOOT_MAGIC_UNSET 3
#define BOOT_MAGIC_BAD 2
#define BOOT_FLAG_SET 1
#define BOOT_FLAG_UNSET 3
#define BOOT_SWAP_TYPE_PERM 3
#define BOOT_SWAP_TYPE_TEST 2
#define BOOT_EBADVECT 11
#define BOOT_EBADIMAGE 12
#define MGMT_ERR_EINVAL 2
#define MGMT_ERR_ENOENT 3
#define MGMT_ERR_EUNKNOWN 4
#define MGMT_ERR_ENOTSUP 5
#define NMGR_OP_READ 0
#define BOOT_HOOK_REGULAR 99
#define FIH_BOOT_HOOK_REGULAR 98
#define FIH_SUCCESS 1
#define FIH_FAILURE 0
#define FIH_DECLARE(name,value) int name = value
#define FIH_CALL(fn,result,...) result = fn(__VA_ARGS__)
#define FIH_EQ(a,b) ((a)==(b))
#define FIH_NOT_EQ(a,b) ((a)!=(b))
#define BOOT_HOOK_CALL(...) BOOT_HOOK_REGULAR
#define BOOT_HOOK_CALL_FIH(name,regular,result,...) result = FIH_BOOT_HOOK_REGULAR
#define BOOT_LOG_ERR(...) (void)0
#define BOOT_LOG_DBG(...) (void)0
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define CBOR_EXTRA_STATES 0
#define BOOT_CURR_IMG(state) ((state)->current)
#define BOOT_IMG_AREA(state,slot) ((state)->areas[slot])
#define IMAGES_ITER(index) for ((index)=0; (index)<1; ++(index))
struct flash_area { int id; };
struct image_header { uint32_t ih_magic; };
struct boot_swap_state { int magic, image_ok, copy_done; };
struct boot_loader_state { int current; const struct flash_area *areas[2]; };
struct zcbor_string { const uint8_t *value; size_t len; };
typedef int zcbor_state_t;
struct zcbor_map_decode_key_val { const char *key; void *output; };
#define ZCBOR_MAP_DECODE_KEY_DECODER(key,fn,out) {key,out}
enum bootutil_data_source { BOOTUTIL_DATA_SOURCE_RAM=0x35, BOOTUTIL_DATA_SOURCE_FLASH=0xca };
static struct flash_area areas[2] = {{0},{1}};
static struct boot_loader_state loader;
static struct boot_swap_state trailers[2];
static bool request_confirm, request_hash, fail_validation, fail_open;
static uint8_t requested_hash[32];
static int writes[2], last_error, list_calls, close_calls, clear_calls, validations;
static void zcbor_new_decode_state(zcbor_state_t *s,size_t n,uint8_t *b,int l,int x,void *p,int z)
{ (void)s;(void)n;(void)b;(void)l;(void)x;(void)p;(void)z; }
static int zcbor_map_decode_bulk(zcbor_state_t *s,struct zcbor_map_decode_key_val *keys,size_t n,size_t *decoded)
{
    (void)s;*decoded=n;
    for (size_t i=0;i<n;i++) {
        if (!strcmp(keys[i].key,"confirm")) *(bool *)keys[i].output=request_confirm;
        if (!strcmp(keys[i].key,"hash")) *(struct zcbor_string *)keys[i].output=
            (struct zcbor_string){requested_hash,request_hash?32:0};
    }
    return 0;
}
static int flash_area_read(const struct flash_area *fa,uint32_t off,void *out,size_t len)
{ (void)fa;(void)off;assert(len==sizeof(struct image_header));*(struct image_header *)out=(struct image_header){IMAGE_MAGIC};return 0; }
static int bootutil_img_validate_source(enum bootutil_data_source source,struct boot_loader_state *s,
 struct image_header *h,const struct flash_area *fa,uint8_t *b,size_t l,void *seed,int sl,void *hash)
{
    (void)s;(void)h;(void)fa;(void)b;(void)l;(void)seed;(void)sl;(void)hash;
    assert(source==BOOTUTIL_DATA_SOURCE_FLASH);++validations;return fail_validation?FIH_FAILURE:FIH_SUCCESS;
}
static int boot_serial_get_hash(const struct image_header *h,const struct flash_area *fa,uint8_t *hash)
{ (void)h;memset(hash,0,32);hash[0]=fa->id;return 0; }
static int boot_read_swap_state(const struct flash_area *fa,struct boot_swap_state *out)
{ *out=trailers[fa->id];return 0; }
static int boot_write_image_ok(const struct flash_area *fa)
{ trailers[fa->id].image_ok=BOOT_FLAG_SET;++writes[fa->id];return 0; }
static int boot_write_magic(const struct flash_area *fa)
{ trailers[fa->id].magic=BOOT_MAGIC_GOOD;++writes[fa->id];return 0; }
static int boot_write_swap_info(const struct flash_area *fa,int type,int image)
{ (void)type;(void)image;++writes[fa->id];return 0; }
static int flash_area_to_image(const struct flash_area *fa) { (void)fa;return 0; }
static int boot_set_pending_multi(int image,bool confirm)
{ (void)image;(void)confirm;assert(!"RAM-load must select its requested slot");return -1; }
static void bs_list(struct boot_loader_state *s,char *b,int l)
{ (void)s;(void)b;(void)l;++list_calls; }
static void bs_rc_rsp(int rc) { last_error=rc; }
static struct boot_loader_state *boot_get_loader_state(void) { return &loader; }
static void boot_state_init(struct boot_loader_state *s)
{ *s=(struct boot_loader_state){0,{&areas[0],&areas[1]}}; }
static int boot_open_all_flash_areas(struct boot_loader_state *s)
{ (void)s;return fail_open?-1:0; }
static void boot_close_all_flash_areas(struct boot_loader_state *s) { (void)s;++close_calls; }
static void boot_state_clear(struct boot_loader_state *s) { memset(s,0,sizeof(*s));++clear_calls; }
static void reset_cbor_state(void) {}
static zcbor_state_t cbor_state[1];
static void zcbor_map_start_encode(zcbor_state_t *s,int n) { (void)s;(void)n; }
static void zcbor_map_end_encode(zcbor_state_t *s,int n) { (void)s;(void)n; }
static void zcbor_tstr_put_lit_cast(zcbor_state_t *s,const char *k) { (void)s;(void)k; }
static void zcbor_int32_put(zcbor_state_t *s,int rc) { (void)s;last_error=rc; }
static void boot_serial_output(void) {}
'''
MAIN = r'''
static void reset(void)
{
    memset(writes,0,sizeof(writes));
    trailers[0]=(struct boot_swap_state){BOOT_MAGIC_UNSET,BOOT_FLAG_UNSET,BOOT_FLAG_UNSET};
    trailers[1]=trailers[0];
    request_confirm=request_hash=fail_validation=fail_open=false;
    memset(requested_hash,0,sizeof(requested_hash));
    last_error=list_calls=close_calls=clear_calls=validations=0;
}
int main(void)
{
    reset();request_hash=true;requested_hash[0]=0;
    bs_list_set(1,NULL,0);
    assert(trailers[0].magic==BOOT_MAGIC_GOOD && trailers[0].image_ok==BOOT_FLAG_UNSET);
    assert(writes[1]==0 && validations==1 && clear_calls==1 && close_calls==1);
    request_confirm=true;bs_list_set(1,NULL,0);
    assert(trailers[0].image_ok==BOOT_FLAG_SET && writes[1]==0);

    reset();request_hash=true;requested_hash[0]=1;
    bs_list_set(1,NULL,0);
    assert(trailers[1].magic==BOOT_MAGIC_GOOD && writes[0]==0);
    request_confirm=true;bs_list_set(1,NULL,0);
    assert(trailers[1].image_ok==BOOT_FLAG_SET && writes[0]==0);

    reset();request_confirm=true;bs_list_set(1,NULL,0);
    assert(trailers[1].magic==BOOT_MAGIC_GOOD && trailers[1].image_ok==BOOT_FLAG_SET && writes[0]==0);

    reset();request_hash=true;requested_hash[0]=7;bs_list_set(1,NULL,0);
    assert(last_error==MGMT_ERR_ENOENT && writes[0]==0 && writes[1]==0);

    reset();request_hash=true;fail_validation=true;bs_list_set(1,NULL,0);
    assert(last_error==MGMT_ERR_ENOENT && validations==2 && writes[0]==0 && writes[1]==0);

    reset();fail_open=true;bs_list_set(1,NULL,0);
    assert(last_error==MGMT_ERR_EUNKNOWN && close_calls==0 && clear_calls==1 && writes[0]==0 && writes[1]==0);
    puts("PASS: RAM-load serial hash-selected slots, test confirmation, validation/open failure exits");
}
'''
program = PRELUDE + "\nstatic int " + function(public,"boot_set_next")
program += "\nstatic void " + function(serial,"bs_set")
program += "\nstatic void " + function(serial,"bs_list_set") + MAIN
with tempfile.TemporaryDirectory(prefix="mcuboot-serial-revert-") as directory:
    source = Path(directory)/"test.c"
    binary = Path(directory)/"test"
    source.write_text(program)
    subprocess.run([os.environ.get("CC","gcc"),"-std=c11","-Wall","-Wextra",
                    "-Wno-unused-function","-Werror",str(source),"-o",str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
