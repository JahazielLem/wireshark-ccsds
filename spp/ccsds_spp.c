/* spp.c
* SPDX-FileCopyrightText: © 2026 Kevin Leon
* SPDX-License-Identifier: GPL-3.0-or-later
*
* By now not support secondary header dissection
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/unit_strings.h>
#include <wireshark.h>
#include <wiretap/wtap.h>

/**
 * https://ccsds.org/wp-content/uploads/gravity_forms/5-448e85c647331d9cbaf66c096458bdd5/2025/01//133x0b2e2.pdf?gv-iframe=true
*/

#define CCSDS_PRIMARY_HEADER_LENGTH (6)
#define CCSDS_SPP_VERSION 0 // 4.1.3.2.2 133B2 SPP CCSDS
#define HDR_MASK_VERSION 0xe000
#define HDR_MASK_TYPE    0x1000
#define HDR_MASK_SECHDR  0x0800
#define HDR_MASK_APID    0x07FF
#define HDR_MASK_SEQFLAG 0xc000
#define HDR_MASK_SEQNUM  0x3fff
#define IDLE_APID         0b1111111111

// Dissector handles
static dissector_handle_t handle_ccsds_spp_rpi;
// Protocol handle
static int proto_ccsds_spp;

/* primary ccsds header */
static int hf_ccsds_spp_header_flags;
static int hf_ccsds_spp_version;
static int hf_ccsds_spp_type;
static int hf_ccsds_spp_secheader;
static int hf_ccsds_spp_apid;
static int hf_ccsds_spp_seqflag;
static int hf_ccsds_spp_seqnum;
static int hf_ccsds_spp_length;

/* Initialize the subtree pointers */
static int ett_ccsds_spp;
static int ett_ccsds_spp_primary_header_flags;
static int ett_ccsds_spp_primary_header;
static int ett_ccsds_spp_secondary_header;

static expert_field ei_ccsds_length_error;
static expert_field ei_ccsds_version_error;

static gint spp_endianness = 1; // 0 = big, 1 = little
static int spp_encoding = ENC_BIG_ENDIAN;

static const value_string table_frame_type[] = {
  {0x00, "Telemetry"},
  {0x01, "Telecommand"},
  {0, NULL}
};

static const enum_val_t dissect_endianes[] = {
  { "little", "Use Little Endian", TRUE },
  { "big",  "Use Big Endian", FALSE },
  { NULL, NULL, 0 }
};

static int * const header_flags[] = {
  &hf_ccsds_spp_version,
  &hf_ccsds_spp_type,
  &hf_ccsds_spp_secheader,
  &hf_ccsds_spp_apid,
  NULL
};

static const value_string ccsds_primary_header_sequence_flags[] = {
  {  0, "Continuation segment" },
  {  1, "First segment" },
  {  2, "Last segment" },
  {  3, "Unsegmented data" },
  {  0, NULL }
};

static int dissect_ccsds_spp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_){
  int offset = 0;
  proto_item  *ccsds_packet;
  proto_tree  *ccsds_tree;
  proto_item  *primary_header;
  proto_tree  *primary_header_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CCSDS SPP");
  col_set_str(pinfo->cinfo, COL_INFO, "SPP Packet");

  int reported_length = tvb_reported_length_remaining(tvb, offset);
  int ccsds_length = spp_endianness ? tvb_get_letohs(tvb, 4) : tvb_get_ntohs(tvb, 4);

  spp_encoding = (spp_endianness == 1) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

  const uint16_t header_info  = spp_endianness ? tvb_get_letohs(tvb, 0) : tvb_get_ntohs(tvb, 0);
  const uint16_t seqflag_info = spp_endianness ? tvb_get_letohs(tvb, 2) : tvb_get_ntohs(tvb, 2);
  
  const uint16_t seqflag = (seqflag_info & HDR_MASK_SEQFLAG) >> 14;
  col_add_fstr(pinfo->cinfo, COL_INFO, "APID: %4d (0x%03X) - Flags: 0x%03X (%s)", (header_info&HDR_MASK_APID), (header_info&HDR_MASK_APID),
  seqflag, try_val_to_str(seqflag, ccsds_primary_header_sequence_flags));

  ccsds_packet = proto_tree_add_item(tree, proto_ccsds_spp, tvb, 0, -1, ENC_NA);
  ccsds_tree   = proto_item_add_subtree(ccsds_packet, ett_ccsds_spp);

  /* build the ccsds primary header tree */
  primary_header_tree = proto_tree_add_subtree(ccsds_tree, tvb, offset, CCSDS_PRIMARY_HEADER_LENGTH,
                            ett_ccsds_spp_primary_header, &primary_header, "Primary CCSDS Header");
  proto_item *pi_mask = proto_tree_add_bitmask(primary_header_tree, tvb, offset, hf_ccsds_spp_header_flags,
                    ett_ccsds_spp_primary_header_flags, header_flags, spp_encoding);
  
  const uint16_t version = (header_info & HDR_MASK_VERSION) >> 13;
  if (version != CCSDS_SPP_VERSION){
    expert_add_info(pinfo, pi_mask, &ei_ccsds_version_error);
  }
  offset += 2;

  proto_tree_add_item(primary_header_tree, hf_ccsds_spp_seqflag, tvb, offset, 2, spp_encoding);
  proto_tree_add_item(primary_header_tree, hf_ccsds_spp_seqnum, tvb, offset, 2, spp_encoding);
  offset += 2;

  proto_item *pt_length = proto_tree_add_item(primary_header_tree, hf_ccsds_spp_length, tvb, offset, 2, spp_encoding);
  if (ccsds_length > reported_length){
    expert_add_info(pinfo, pt_length, &ei_ccsds_length_error);
  }
  offset += 2;
  proto_item_set_end(primary_header, tvb, offset);

  /* Give the data dissector any bytes past the CCSDS packet length */
  call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
  return tvb_captured_length(tvb);
}

void proto_register_ccsds_spp(void){
  static hf_register_info hf[] = {
    {&hf_ccsds_spp_header_flags, {"Header Flags", "ccsds-spp.header_flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_ccsds_spp_version, {"Version", "ccsds-spp.version", FT_UINT16, BASE_DEC, NULL, HDR_MASK_VERSION, NULL, HFILL}},
    {&hf_ccsds_spp_type, {"Type", "ccsds-spp.type", FT_UINT16, BASE_DEC, VALS(table_frame_type), HDR_MASK_TYPE, NULL, HFILL}},
    {&hf_ccsds_spp_secheader, {"Secondary Header Flag", "ccsds-spp.sec_flag", FT_BOOLEAN, 16, NULL, HDR_MASK_SECHDR, "Secondary Header Present", HFILL}},
    {&hf_ccsds_spp_apid, {"APID", "ccsds-spp.apid", FT_UINT16, BASE_DEC, NULL, HDR_MASK_APID, NULL, HFILL}},
    {&hf_ccsds_spp_seqflag, {"Sequence Flags", "ccsds-spp.seqflag", FT_UINT16, BASE_DEC, VALS(ccsds_primary_header_sequence_flags), HDR_MASK_SEQFLAG, NULL, HFILL}},
    {&hf_ccsds_spp_seqnum, {"Sequence Number", "ccsds-spp.seqnum", FT_UINT16, BASE_DEC, NULL, HDR_MASK_SEQNUM, NULL, HFILL}},
    {&hf_ccsds_spp_length, {"Packet Length", "ccsds-spp.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
  };

  static int *ett[] = {
    &ett_ccsds_spp_primary_header_flags,
    &ett_ccsds_spp,
    &ett_ccsds_spp_primary_header,
    &ett_ccsds_spp_secondary_header,
  };

  static ei_register_info ei[] = {
    { &ei_ccsds_version_error,  { "ccsds-spp.version.error", PI_PROTOCOL, PI_WARN, "Version is other than 0. 4.1.3.2.2 133B2 SPP CCSDS", EXPFILL }},
    { &ei_ccsds_length_error, { "ccsds-spp.length.error", PI_MALFORMED, PI_ERROR, "Length field value is greater than the packet seen on the wire", EXPFILL }},
  };

  // Register protocol
  proto_ccsds_spp = proto_register_protocol("CCSDS Space Packet Protocol", "CCSDS SPP", "ccsds-spp");
  // Register header fields
  proto_register_field_array(proto_ccsds_spp, hf, array_length(hf));
  // Register subtree
  proto_register_subtree_array(ett, array_length(ett));
  expert_module_t* expert_ccsds_spp = expert_register_protocol(proto_ccsds_spp);
  expert_register_field_array(expert_ccsds_spp, ei, array_length(ei));

  // Register dissectors
  handle_ccsds_spp_rpi = register_dissector("ccsds_spp", dissect_ccsds_spp, proto_ccsds_spp);
  /* Register preferences module */
  module_t *ccsds_module = prefs_register_protocol(proto_ccsds_spp, NULL);
  prefs_register_enum_preference(ccsds_module, "global_pref_checkword",
        "How to handle the CCSDS endianes",
        "Specify how the dissector should handle the CCSDS endianes",
        &spp_endianness, dissect_endianes, false);
}

void proto_reg_handoff_ccsds_spp(void){
  dissector_add_uint("wtap_encap", WTAP_ENCAP_USER1, handle_ccsds_spp_rpi);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
