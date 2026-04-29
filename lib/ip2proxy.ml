open Stdint

module Database = struct
  type meta_data = {
    fs : in_channel;
    db_type : int;
    db_column : int;
    db_year : int;
    db_month : int;
    db_day : int;
    ipv4_db_count : uint32;
    ipv4_base_addr : uint32;
    ipv6_db_count : uint32;
    ipv6_base_addr : uint32;
    ipv4_index_base_addr : uint32;
    ipv6_index_base_addr : uint32;
    ipv4_column_size : uint32;
    ipv6_column_size : uint32
  }

  type ip2proxy_record = {
    country_short : string;
    country_long : string;
    region : string;
    city : string;
    isp : string;
    proxy_type : string;
    is_proxy : int;
    domain : string;
    usage_type : string;
    asn : string;
    asys : string;
    last_seen : int;
    threat : string;
    provider : string;
    fraud_score : string
  }

  exception Ip2proxy_exception of string

  let get_api_version = "3.2.0"

  let load_mesg mesg =
    {
    country_short = mesg;
    country_long = mesg;
    region = mesg;
    city = mesg;
    isp = mesg;
    proxy_type = mesg;
    is_proxy = -1;
    domain = mesg;
    usage_type = mesg;
    asn = mesg;
    asys = mesg;
    last_seen = 0;
    threat = mesg;
    provider = mesg;
    fraud_score = mesg
    }

  let get_bytes inc pos len =
    try
      seek_in inc pos;
      let res = Bytes.create len in
      let _ = input inc res 0 len in
      res
    with e ->
      raise e

  let read_uint8_row row pos =
    Bytes.get_uint8 row pos

  let read_uint32_row row pos =
    Uint32.of_bytes_little_endian row pos

  let read_uint128_row row pos =
    Uint128.of_bytes_little_endian row pos

  let read_str meta pos =
    let row = get_bytes meta.fs pos 256 in (* max size of string field + 1 byte for the length *)
    let len = read_uint8_row row 0 in
    let data = Bytes.sub row 1 len in
    Bytes.to_string data

  let read_col_country_row meta row db_type col =
    let x = "This parameter is unavailable for selected data file. Please upgrade the data file." in
    let col_pos = col.(db_type) in
    
    if col_pos == 0
    then
      (x, x)
    else
      let col_offset = (col_pos - 2) lsl 2 in
      let x0 = Uint32.to_int (read_uint32_row row col_offset) in
      let x1 = read_str meta x0 in
      let x2 = read_str meta (x0 + 3) in
      (x1, x2)

  let read_col_string_row meta row db_type col =
    let col_pos = col.(db_type) in
    
    if col_pos == 0
    then
      "This parameter is unavailable for selected data file. Please upgrade the data file."
    else
      let col_offset = (col_pos - 2) lsl 2 in
      read_str meta (Uint32.to_int (read_uint32_row row col_offset))

  let read_col_int_row row db_type col =
    let col_pos = col.(db_type) in

    if col_pos == 0
    then
      0
    else
      let col_offset = (col_pos - 2) lsl 2 in
      Uint32.to_int (read_uint32_row row col_offset)

  (* let read_float32 row = *)
    (* let rec pow2 = function *)
      (* | 0 -> 1 *)
      (* | n -> 2 * (pow2 (n - 1)) *)
    (* in *)
    (* let getbit b n = (b land (pow2 n)) lsr n in *)
    (* let b0 = Uint8.to_int (Uint8.of_bytes_little_endian row 0) in *)
    (* let b1 = Uint8.to_int (Uint8.of_bytes_little_endian row 1) in *)
    (* let b2 = Uint8.to_int (Uint8.of_bytes_little_endian row 2) in *)
    (* let b3 = Uint8.to_int (Uint8.of_bytes_little_endian row 3) in *)
    (* let sign = getbit b3 7 *)
    (* and exponent = 128*(getbit b3 6) + 64*(getbit b3 5) + 32*(getbit b3 4) + 16*(getbit b3 3) + 8*(getbit b3 2) + 4*(getbit b3 1) + 2*(getbit b3 0) + (getbit b2 7) *)
    (* and significand = b0 + 256*b1 + 65536*(((b2 lsl 1) land 0xFF ) lsr 1) in *)
    (* let max_significand = (float (pow2 23)) -. 1.0 in *)
    (* if exponent = 255 then *)
      (* if significand = 0 then *)
        (* if sign = 0 then neg_infinity else infinity *)
      (* else *)
        (* nan *)
    (* else if exponent = 0 then *)
      (* if significand = 0 then *)
        (* if sign = 0 then 0.0 else -0.0 *)
      (* else *)
        (* let fs = if sign = 0 then 1.0 else -1.0 *)
        (* and fexp = (2.0) ** (-126.0) *)
        (* and fsig = ((float significand) /. max_significand) in *)
        (* fs *. fexp *. fsig *)
    (* else *)
      (* let fs = if sign = 0 then 1.0 else -1.0 *)
      (* and fexp = (2.0) ** (float (exponent - 127)) *)
      (* and fsig = 1.0 +. ((float significand) /. max_significand) in *)
      (* fs *. fexp *. fsig *)

  (* let read_float_row row pos = *)
    (* let data = Bytes.sub row pos 4 in *)
    (* read_float32 data *)

  (* let read_col_float_row row db_type col = *)
    (* let col_pos = col.(db_type) in *)

    (* if col_pos == 0 *)
    (* then *)
      (* 0. *)
    (* else *)
      (* let col_offset = (col_pos - 2) lsl 2 in *)
      (* read_float_row row col_offset *)

  (* let read_col_float_string_row meta row db_type col = *)
    (* let col_pos = col.(db_type) in *)

    (* if col_pos == 0 *)
    (* then *)
      (* 0. *)
    (* else *)
      (* let col_offset = (col_pos - 2) lsl 2 in *)
      (* let x = Uint32.to_int (read_uint32_row row col_offset) in *)
      (* let n = read_str meta x in *)
      (* Float.of_string n *)

  (** Initialize with the IP2Proxy BIN database path and read metadata *)
  let open_db bin_path =
    let inc = open_in_bin bin_path in
    let row = get_bytes inc 0 64 in
    
    let db_type = read_uint8_row row 0 in
    let db_column = read_uint8_row row 1 in
    let db_year = read_uint8_row row 2 in
    let db_month = read_uint8_row row 3 in
    let db_day = read_uint8_row row 4 in
    let ipv4_db_count = read_uint32_row row 5 in
    let ipv4_base_addr = read_uint32_row row 9 in
    let ipv6_db_count = read_uint32_row row 13 in
    let ipv6_base_addr = read_uint32_row row 17 in
    let ipv4_index_base_addr = read_uint32_row row 21 in
    let ipv6_index_base_addr = read_uint32_row row 25 in
    let product_code = read_uint8_row row 29 in
    
    (* check if is correct BIN (should be 2 for IP2Proxy BIN file), also checking for zipped file (PK being the first 2 chars) *)
    if (product_code != 2 && db_year >= 21) || (db_type == 80 && db_column == 75)
    then
      raise (Ip2proxy_exception "Incorrect IP2Proxy BIN file format. Please make sure that you are using the latest IP2Proxy BIN file.")
    else
      {
        fs = inc;
        db_type = db_type;
        db_column = db_column;
        db_year = db_year;
        db_month = db_month;
        db_day = db_day;
        ipv4_db_count = ipv4_db_count;
        ipv4_base_addr = ipv4_base_addr;
        ipv6_db_count = ipv6_db_count;
        ipv6_base_addr = ipv6_base_addr;
        ipv4_index_base_addr = ipv4_index_base_addr;
        ipv6_index_base_addr = ipv6_index_base_addr;
        ipv4_column_size = Uint32.shift_left (Uint32.of_int db_column) 2; (* 4 bytes each column *)
        ipv6_column_size = Uint32.add (Uint32.of_int 16) (Uint32.shift_left (Uint32.of_int (db_column - 1)) 2); (* 4 bytes each column, except IPFrom column which is 16 bytes *)
      }
  
  (** Close input channel *)
  let close_db meta = close_in_noerr meta.fs

  let read_record meta row db_type =
    let country_position = [|0; 2; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3|] in
    let region_position = [|0; 0; 0; 4; 4; 4; 4; 4; 4; 4; 4; 4; 4|] in
    let city_position = [|0; 0; 0; 5; 5; 5; 5; 5; 5; 5; 5; 5; 5|] in
    let isp_position = [|0; 0; 0; 0; 6; 6; 6; 6; 6; 6; 6; 6; 6|] in
    let proxy_type_position = [|0; 0; 2; 2; 2; 2; 2; 2; 2; 2; 2; 2; 2|] in
    let domain_position = [|0; 0; 0; 0; 0; 7; 7; 7; 7; 7; 7; 7; 7|] in
    let usage_type_position = [|0; 0; 0; 0; 0; 0; 8; 8; 8; 8; 8; 8; 8|] in
    let asn_position = [|0; 0; 0; 0; 0; 0; 0; 9; 9; 9; 9; 9; 9|] in
    let asys_position = [|0; 0; 0; 0; 0; 0; 0; 10; 10; 10; 10; 10; 10|] in
    let last_seen_position = [|0; 0; 0; 0; 0; 0; 0; 0; 11; 11; 11; 11; 11|] in
    let threat_position = [|0; 0; 0; 0; 0; 0; 0; 0; 0; 12; 12; 12; 12|] in
    let provider_position = [|0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 13; 13|] in
    let fraud_score_position = [|0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 14|] in
    
    let country_short, country_long = read_col_country_row meta row db_type country_position in
    let region = read_col_string_row meta row db_type region_position in
    let city = read_col_string_row meta row db_type city_position in
    let isp = read_col_string_row meta row db_type isp_position in
    let proxy_type = read_col_string_row meta row db_type proxy_type_position in
    let domain = read_col_string_row meta row db_type domain_position in
    let usage_type = read_col_string_row meta row db_type usage_type_position in
    let asn = read_col_string_row meta row db_type asn_position in
    let asys = read_col_string_row meta row db_type asys_position in
    let last_seen = read_col_int_row row db_type last_seen_position in
    let threat = read_col_string_row meta row db_type threat_position in
    let provider = read_col_string_row meta row db_type provider_position in
    let fraud_score = read_col_string_row meta row db_type fraud_score_position in
    let is_proxy = if (country_short == "-" || proxy_type == "-") then 0 else if (proxy_type == "DCH" || proxy_type == "SES" || proxy_type == "AIC") then 2 else 1 in
    {
      country_short = country_short;
      country_long = country_long;
      region = region;
      city = city;
      isp = isp;
      proxy_type = proxy_type;
      is_proxy = is_proxy;
      domain = domain;
      usage_type = usage_type;
      asn = asn;
      asys = asys;
      last_seen = last_seen;
      threat = threat;
      provider = provider;
      fraud_score = fraud_score
    }
  
  let rec search_tree meta ip_num db_type low high base_addr col_size ip_type =
    if low <= high
    then
      let mid = Uint32.shift_right_logical (Uint32.add low high) 1 in
      (* ignore (Printf.printf "DEBUG  ----  %s\t%s\t%s\n%!" (Uint32.to_string low) (Uint32.to_string mid) (Uint32.to_string high)); (* %! to flush buffer *) *)
      let row_offset = Uint32.add base_addr (Uint32.mul mid col_size) in
      
      let first_col = Uint32.of_int (if ip_type == 4 then 4 else 16) in
      let read_len = Uint32.add col_size first_col in
      
      let row = get_bytes meta.fs ((Uint32.to_int row_offset) - 1) (Uint32.to_int read_len) in (* reading IP From + whole row + next IP From *)
      
      let ip_from = if ip_type == 4 then Uint32.to_uint128 (read_uint32_row row 0) else read_uint128_row row 0 in
      let ip_to = if ip_type == 4 then Uint32.to_uint128 (read_uint32_row row (Uint32.to_int col_size)) else read_uint128_row row (Uint32.to_int col_size) in
      
      if ip_num >= ip_from && ip_num < ip_to
      then
        let row_len = Uint32.to_int (Uint32.sub col_size first_col) in
        let row2 = Bytes.sub row (Uint32.to_int first_col) row_len in
        
        read_record meta row2 db_type
      else
        if ip_num < ip_from
        then
          search_tree meta ip_num db_type low (Uint32.pred mid) base_addr col_size ip_type
        else
          search_tree meta ip_num db_type (Uint32.succ mid) high base_addr col_size ip_type
    else
      load_mesg "IP address not found."
  
  let search_4 meta ip_num =
    (* ignore (Printf.printf "DEBUG  ----  %s\n%!" (Uint128.to_string ip_num)); (* %! to flush buffer *) *)
    let max4 = Uint128.of_string "4294967295" in
    let ip_num2 = if (Uint128.compare ip_num max4) == 0 then (Uint128.pred ip_num) else ip_num in
    if meta.ipv4_index_base_addr > Uint32.zero
    then
      let index_pos = Uint32.to_int (Uint32.add (Uint128.to_uint32 (Uint128.shift_left (Uint128.shift_right_logical ip_num2 16) 3)) meta.ipv4_index_base_addr) in
      let row = get_bytes meta.fs (index_pos - 1) 8 in (* 4 bytes for each IP From & IP To *)
      let low = read_uint32_row row 0 in
      let high = read_uint32_row row 4 in
      search_tree meta ip_num2 meta.db_type low high meta.ipv4_base_addr meta.ipv4_column_size 4
    else
      search_tree meta ip_num2 meta.db_type Uint32.zero meta.ipv4_db_count meta.ipv4_base_addr meta.ipv4_column_size 4
  
  let search_6 meta ip_num =
    let max6 = Uint128.of_string "340282366920938463463374607431768211455" in
    let ip_num2 = if (Uint128.compare ip_num max6) == 0 then (Uint128.pred ip_num) else ip_num in
    if meta.ipv6_index_base_addr > Uint32.zero
    then
      let index_pos = Uint32.to_int (Uint32.add (Uint128.to_uint32 (Uint128.shift_left (Uint128.shift_right_logical ip_num2 112) 3)) meta.ipv6_index_base_addr) in
      let row = get_bytes meta.fs (index_pos - 1) 8 in (* 4 bytes for each IP From & IP To *)
      let low = read_uint32_row row 0 in
      let high = read_uint32_row row 4 in
      
      search_tree meta ip_num2 meta.db_type low high meta.ipv6_base_addr meta.ipv6_column_size 6
    else
      search_tree meta ip_num2 meta.db_type Uint32.zero meta.ipv6_db_count meta.ipv6_base_addr meta.ipv6_column_size 6
  
  (** Query proxy data for IP address *)
  let query meta ip =
    begin
      let from_v4_mapped = Uint128.of_string "281470681743360" in
      let to_v4_mapped = Uint128.of_string "281474976710655" in
      let from_6_to_4 = Uint128.of_string "42545680458834377588178886921629466624" in
      let to_6_to_4 = Uint128.of_string "42550872755692912415807417417958686719" in
      let from_teredo = Uint128.of_string "42540488161975842760550356425300246528" in
      let to_teredo = Uint128.of_string "42540488241204005274814694018844196863" in
      let last_32_bits = Uint128.of_string "4294967295" in
      
      (* Printexc.record_backtrace true; *)
      try
        let x = Ipaddr.V4.of_string_exn ip in
        let ip_num = Uint32.to_uint128 (Uint32.of_bytes_big_endian (Bytes.of_string (Ipaddr.V4.to_octets x)) 0) in (* big endian because is network byte order *)
        search_4 meta ip_num
      with _ ->
        (* let msg = Printexc.to_string e and stack = Printexc.get_backtrace () in *)
        (* ignore (Printf.printf "ERROR  ----  %s\n%s\n%!" msg stack); (* %! to flush buffer *) *)
        try
          let x = Ipaddr.V6.of_string_exn ip in
          let ip_num = Uint128.of_bytes_big_endian (Bytes.of_string (Ipaddr.V6.to_octets x)) 0 in (* big endian because is network byte order *)
          if ip_num >= from_v4_mapped && ip_num <= to_v4_mapped
          then
            search_4 meta (Uint128.sub ip_num from_v4_mapped)
          else if ip_num >= from_6_to_4 && ip_num <= to_6_to_4
          then
            search_4 meta (Uint128.logand (Uint128.shift_right_logical ip_num 80) last_32_bits)
          else if ip_num >= from_teredo && ip_num <= to_teredo
          then
            search_4 meta (Uint128.logand (Uint128.lognot ip_num) last_32_bits)
          else if meta.ipv6_db_count > (Uint32.of_int 0)
          then
            search_6 meta ip_num
          else
            load_mesg "IPv6 address missing in IPv4 BIN."
        with _ ->
          load_mesg "Invalid IP address."
    end
  
end
