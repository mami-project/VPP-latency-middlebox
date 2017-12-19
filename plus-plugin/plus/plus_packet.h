#ifndef included_plus_packet_h
#define included_plus_packet_h

/**
 * @brief Normal PLUS header.
 */
typedef struct _plus_header
{
  u32 magic_and_flags;
  u64 CAT;
  u32 PSN;
  u32 PSE;
} __attribute__ ((packed)) plus_header_t;

/**
 * @brief Extended PLUS hop count header.
 */
typedef struct _plus_ext_hop_c_h {
  u8 PCF_type;
  u8 PCF_len_and_II;
  u8 PCF_hop_c;
} __attribute__ ((packed)) plus_ext_hop_c_h_t;

/* PLUS header (with optional part (PCF Type, ...)
 *
 * 0           8           14 16                  28     31
 * --------------------------------------------------------
 * |   Magic 0xd8007ff                            |L|R|S|X|
 * --------------------------------------------------------
 * |   Connection and                                     |
 * |   Association Token (CAT)                            |
 * --------------------------------------------------------
 * |  Packet Serial Number (PSN)                          |
 * --------------------------------------------------------
 * |  Packet Serial Echo (PSE)                            |
 * --------------------------------------------------------
 * |  PCF Type | PCF Len | II |   PCF Value               |
 * --------------------------------------------------------
 */

#endif /* included_plus_packet_h */

