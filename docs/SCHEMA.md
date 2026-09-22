# Schema

Generated from the released files by `corpus/preparer_depot.py`.
Every table holds one row per file, keyed by `sha256`.

A field is `null` when the corresponding structure is absent from
the binary, never when a measurement was skipped. A `null`, a
measured zero and a measured `false` are three distinct states.

## `general_info.parquet`

Identity, size, file type, hashes, dates.

- rows: 100 909
- columns: 16

| Column | Type | Nulls |
|---|---|---|
| `sha256` | string | 0 |
| `label` | string | 0 |
| `packing` | string | 0 |
| `family` | string | 30 186 |
| `date_compilation` | string | 15 784 |
| `annee_compilation` | int16 | 15 784 |
| `date_premiere_vue` | string | 84 407 |
| `pe_parsed` | bool | 0 |
| `bloc_present` | bool | 0 |
| `general_info__size_bytes` | int64 | 0 |
| `general_info__md5` | string | 0 |
| `general_info__sha1` | string | 0 |
| `general_info__imphash` | string | 0 |
| `general_info__tlsh` | string | 0 |
| `general_info__ssdeep` | string | 0 |
| `general_info__file_type` | string | 0 |

## `header.parquet`

DOS, COFF, optional and Rich headers, checksum.

- rows: 100 909
- columns: 90

| Column | Type | Nulls |
|---|---|---|
| `dos_header__magic` | int64 | 0 |
| `dos_header__used_bytes_in_last_page` | int64 | 0 |
| `dos_header__file_size_in_pages` | int64 | 0 |
| `dos_header__numberof_relocation` | int64 | 0 |
| `dos_header__header_size_in_paragraphs` | int64 | 0 |
| `dos_header__minimum_extra_paragraphs` | int64 | 0 |
| `dos_header__maximum_extra_paragraphs` | int64 | 0 |
| `dos_header__initial_relative_ss` | int64 | 0 |
| `dos_header__initial_sp` | int64 | 0 |
| `dos_header__checksum` | int64 | 0 |
| `dos_header__initial_ip` | int64 | 0 |
| `dos_header__initial_relative_cs` | int64 | 0 |
| `dos_header__addressof_relocation_table` | int64 | 0 |
| `dos_header__overlay_number` | int64 | 0 |
| `dos_header__oem_id` | int64 | 0 |
| `dos_header__oem_info` | int64 | 0 |
| `dos_header__addressof_new_exeheader` | int64 | 0 |
| `dos_header__e_lfanew_raw` | int64 | 0 |
| `dos_header__reserved1_hex` | string | 0 |
| `dos_header__reserved2_hex` | string | 0 |
| `dos_header__reserved_nonzero` | int64 | 0 |
| `dos_header__raw_hex` | string | 0 |
| `dos_header__raw_size` | int64 | 0 |
| `dos_stub__size` | int64 | 0 |
| `dos_stub__entropy` | double | 1 166 |
| `dos_stub__is_standard_ms` | int64 | 1 166 |
| `dos_stub__sha256` | string | 1 166 |
| `dos_stub__head_hex` | string | 1 166 |
| `dos_stub__raw_hex` | string | 1 166 |
| `dos_stub__raw_truncated` | int64 | 1 166 |
| `dos_stub__tail_hex` | string | 100 902 |
| `dos_stub__message` | string | 1 578 |
| `dos_stub__message_is_standard` | int64 | 1 166 |
| `rich_header__has_rich_header` | int64 | 0 |
| `rich_header__key` | int64 | 36 966 |
| `rich_header__entries` | string | 100 909 |
| `rich_header__raw_hex` | string | 37 483 |
| `rich_header__raw_offset` | int64 | 37 483 |
| `rich_header__raw_size` | int64 | 37 483 |
| `rich_header__entry_count` | int64 | 36 966 |
| `rich_header__entries__n` | int64 | 36 966 |
| `file_header__machine` | string | 0 |
| `file_header__numberof_sections` | int64 | 0 |
| `file_header__time_date_stamp` | int64 | 0 |
| `file_header__pointerto_symbol_table` | int64 | 0 |
| `file_header__numberof_symbols` | int64 | 0 |
| `file_header__sizeof_optional_header` | int64 | 0 |
| `file_header__characteristics_raw` | int64 | 0 |
| `file_header__characteristics__longueur` | int32 | 1 |
| `file_header__characteristics__n` | int64 | 0 |
| `optional_header__magic` | string | 0 |
| `optional_header__major_linker_version` | int64 | 0 |
| `optional_header__minor_linker_version` | int64 | 0 |
| `optional_header__sizeof_code` | int64 | 0 |
| `optional_header__sizeof_initialized_data` | int64 | 0 |
| `optional_header__sizeof_uninitialized_data` | int64 | 0 |
| `optional_header__addressof_entrypoint` | int64 | 0 |
| `optional_header__baseof_code` | int64 | 0 |
| `optional_header__baseof_data` | int64 | 9 884 |
| `optional_header__imagebase` | int64 | 0 |
| `optional_header__section_alignment` | int64 | 0 |
| `optional_header__file_alignment` | int64 | 0 |
| `optional_header__major_operating_system_version` | int64 | 0 |
| `optional_header__minor_operating_system_version` | int64 | 0 |
| `optional_header__major_image_version` | int64 | 0 |
| `optional_header__minor_image_version` | int64 | 0 |
| `optional_header__major_subsystem_version` | int64 | 0 |
| `optional_header__minor_subsystem_version` | int64 | 0 |
| `optional_header__win32_version_value` | int64 | 0 |
| `optional_header__sizeof_image` | int64 | 0 |
| `optional_header__sizeof_headers` | int64 | 0 |
| `optional_header__checksum` | int64 | 0 |
| `optional_header__subsystem` | string | 0 |
| `optional_header__dll_characteristics_raw` | int64 | 0 |
| `optional_header__dll_characteristics__n` | int64 | 0 |
| `optional_header__sizeof_stack_reserve` | int64 | 0 |
| `optional_header__sizeof_stack_commit` | int64 | 0 |
| `optional_header__sizeof_heap_reserve` | int64 | 0 |
| `optional_header__sizeof_heap_commit` | int64 | 0 |
| `optional_header__loader_flags` | int64 | 0 |
| `optional_header__numberof_rva_and_size` | int64 | 0 |
| `optional_header__dll_characteristics__longueur` | int32 | 43 968 |
| `checksum_check__checksum_declared` | int64 | 0 |
| `checksum_check__checksum_computed` | int64 | 0 |
| `checksum_check__checksum_valid` | int64 | 0 |
| `checksum_check__checksum_zero` | int64 | 0 |

## `sections.parquet`

Per-section geometry, entropy and permissions.

- rows: 100 909
- columns: 126

| Column | Type | Nulls |
|---|---|---|
| `sections__n` | int64 | 0 |
| `sec_text_n` | int16 | 0 |
| `sec_text_entropie` | float | 21 431 |
| `sec_text_raw` | int64 | 21 431 |
| `sec_text_virtuel` | int64 | 21 431 |
| `sec_text_executable` | bool | 21 431 |
| `sec_text_modifiable` | bool | 21 431 |
| `sec_data_n` | int16 | 0 |
| `sec_data_entropie` | float | 33 801 |
| `sec_data_raw` | int64 | 33 801 |
| `sec_data_virtuel` | int64 | 33 801 |
| `sec_data_executable` | bool | 33 801 |
| `sec_data_modifiable` | bool | 33 801 |
| `sec_rdata_n` | int16 | 0 |
| `sec_rdata_entropie` | float | 39 759 |
| `sec_rdata_raw` | int64 | 39 759 |
| `sec_rdata_virtuel` | int64 | 39 759 |
| `sec_rdata_executable` | bool | 39 759 |
| `sec_rdata_modifiable` | bool | 39 759 |
| `sec_rsrc_n` | int16 | 0 |
| `sec_rsrc_entropie` | float | 15 256 |
| `sec_rsrc_raw` | int64 | 15 256 |
| `sec_rsrc_virtuel` | int64 | 15 256 |
| `sec_rsrc_executable` | bool | 15 256 |
| `sec_rsrc_modifiable` | bool | 15 256 |
| `sec_reloc_n` | int16 | 0 |
| `sec_reloc_entropie` | float | 40 591 |
| `sec_reloc_raw` | int64 | 40 591 |
| `sec_reloc_virtuel` | int64 | 40 591 |
| `sec_reloc_executable` | bool | 40 591 |
| `sec_reloc_modifiable` | bool | 40 591 |
| `sec_idata_n` | int16 | 0 |
| `sec_idata_entropie` | float | 79 498 |
| `sec_idata_raw` | int64 | 79 498 |
| `sec_idata_virtuel` | int64 | 79 498 |
| `sec_idata_executable` | bool | 79 498 |
| `sec_idata_modifiable` | bool | 79 498 |
| `sec_edata_n` | int16 | 0 |
| `sec_edata_entropie` | float | 95 143 |
| `sec_edata_raw` | int64 | 95 143 |
| `sec_edata_virtuel` | int64 | 95 143 |
| `sec_edata_executable` | bool | 95 143 |
| `sec_edata_modifiable` | bool | 95 143 |
| `sec_tls_n` | int16 | 0 |
| `sec_tls_entropie` | float | 87 767 |
| `sec_tls_raw` | int64 | 87 767 |
| `sec_tls_virtuel` | int64 | 87 767 |
| `sec_tls_executable` | bool | 87 767 |
| `sec_tls_modifiable` | bool | 87 767 |
| `sec_pdata_n` | int16 | 0 |
| `sec_pdata_entropie` | float | 91 477 |
| `sec_pdata_raw` | int64 | 91 477 |
| `sec_pdata_virtuel` | int64 | 91 477 |
| `sec_pdata_executable` | bool | 91 477 |
| `sec_pdata_modifiable` | bool | 91 477 |
| `sec_bss_n` | int16 | 0 |
| `sec_bss_entropie` | float | 93 330 |
| `sec_bss_raw` | int64 | 93 330 |
| `sec_bss_virtuel` | int64 | 93 330 |
| `sec_bss_executable` | bool | 93 330 |
| `sec_bss_modifiable` | bool | 93 330 |
| `sec_code_sans_point_n` | int16 | 0 |
| `sec_code_sans_point_entropie` | float | 93 662 |
| `sec_code_sans_point_raw` | int64 | 93 662 |
| `sec_code_sans_point_virtuel` | int64 | 93 662 |
| `sec_code_sans_point_executable` | bool | 93 662 |
| `sec_code_sans_point_modifiable` | bool | 93 662 |
| `sec_data_sans_point_n` | int16 | 0 |
| `sec_data_sans_point_entropie` | float | 93 906 |
| `sec_data_sans_point_raw` | int64 | 93 906 |
| `sec_data_sans_point_virtuel` | int64 | 93 906 |
| `sec_data_sans_point_executable` | bool | 93 906 |
| `sec_data_sans_point_modifiable` | bool | 93 906 |
| `sec_bss_sans_point_n` | int16 | 0 |
| `sec_bss_sans_point_entropie` | float | 94 230 |
| `sec_bss_sans_point_raw` | int64 | 94 230 |
| `sec_bss_sans_point_virtuel` | int64 | 94 230 |
| `sec_bss_sans_point_executable` | bool | 94 230 |
| `sec_bss_sans_point_modifiable` | bool | 94 230 |
| `sec_upx0_sans_point_n` | int16 | 0 |
| `sec_upx0_sans_point_entropie` | float | 93 943 |
| `sec_upx0_sans_point_raw` | int64 | 93 943 |
| `sec_upx0_sans_point_virtuel` | int64 | 93 943 |
| `sec_upx0_sans_point_executable` | bool | 93 943 |
| `sec_upx0_sans_point_modifiable` | bool | 93 943 |
| `sec_upx1_sans_point_n` | int16 | 0 |
| `sec_upx1_sans_point_entropie` | float | 94 002 |
| `sec_upx1_sans_point_raw` | int64 | 94 002 |
| `sec_upx1_sans_point_virtuel` | int64 | 94 002 |
| `sec_upx1_sans_point_executable` | bool | 94 002 |
| `sec_upx1_sans_point_modifiable` | bool | 94 002 |
| `sec_vide_n` | int16 | 0 |
| `sec_vide_entropie` | float | 97 092 |
| `sec_vide_raw` | int64 | 97 092 |
| `sec_vide_virtuel` | int64 | 97 092 |
| `sec_vide_executable` | bool | 97 092 |
| `sec_vide_modifiable` | bool | 97 092 |
| `sec_n` | int16 | 0 |
| `sec_entropie_max` | float | 4 |
| `sec_entropie_min` | float | 4 |
| `sec_entropie_moyenne` | float | 4 |
| `sec_raw_total` | int64 | 0 |
| `sec_raw_max` | int64 | 4 |
| `sec_virtuel_total` | int64 | 0 |
| `sec_n_nom_non_standard` | int16 | 0 |
| `sec_part_nom_non_standard` | float | 4 |
| `sec_n_executable_et_modifiable` | int16 | 0 |
| `sec_n_raw_zero` | int16 | 0 |
| `sec_nom_plus_dense` | string | 4 |
| `section_layout_qc__gaps` | int64 | 0 |
| `section_layout_qc__overlaps` | int64 | 0 |
| `section_layout_qc__zero_raw_size` | int64 | 0 |
| `section_layout_qc__raw_exceeds_virtual` | int64 | 0 |
| `section_layout_qc__unaligned_offset` | int64 | 0 |
| `section_layout_qc__total_slack_bytes` | int64 | 0 |
| `entrypoint_section__ep_rva` | int64 | 0 |
| `entrypoint_section__section_name` | string | 2 521 |
| `entrypoint_section__section_index` | int64 | 2 521 |
| `entrypoint_section__in_last_section` | int64 | 2 521 |
| `entrypoint_section__in_executable_section` | int64 | 2 521 |
| `entrypoint_section__outside_sections` | int64 | 4 |
| `entrypoint_section__section_entropy` | double | 2 521 |

## `imports.parquet`

Imported libraries and functions, delay imports.

- rows: 100 909
- columns: 7 381
- `imp:` columns: 6 240 (imported function, one column per name)
- `delay:` columns: 953 (delay-loaded import, one column per name)
- `dll:` columns: 178 (library name, one column per name)

| Column | Type | Nulls |
|---|---|---|
| `imports__n` | int64 | 0 |
| `delay_imports__n` | int64 | 0 |
| `orphan_dlls__orphans__longueur` | int32 | 27 127 |
| `orphan_dlls__orphans__n` | int64 | 0 |
| `orphan_dlls__n_orphans` | int64 | 0 |
| `orphan_dlls__n_imported` | int64 | 0 |

## `exports.parquet`

Exported functions and forwarders.

- rows: 100 909
- columns: 8 363
- `exp:` columns: 8 349 (exported function, one column per name)

| Column | Type | Nulls |
|---|---|---|
| `exports__present` | int64 | 0 |
| `exports__name` | string | 71 055 |
| `exports__export_flags` | int64 | 71 055 |
| `exports__timestamp` | int64 | 71 055 |
| `exports__major_version` | int64 | 71 055 |
| `exports__minor_version` | int64 | 71 055 |
| `exports__ordinal_base` | int64 | 71 055 |
| `exports__entry_count` | int64 | 71 055 |
| `exports__entries` | string | 100 909 |
| `exports__entries__n` | int64 | 71 055 |

## `misc.parquet`

Data directories, TLS, .NET, resources, signature.

- rows: 100 909
- columns: 353

| Column | Type | Nulls |
|---|---|---|
| `resources__has_resources` | int64 | 0 |
| `resources__node_count` | int64 | 0 |
| `resources__nodes__n` | int64 | 15 813 |
| `resources__total_size` | int64 | 0 |
| `resources__max_entropy` | double | 17 563 |
| `resources__nodes` | string | 100 909 |
| `misc_structures__has_relocations` | int64 | 0 |
| `misc_structures__relocation_count` | int64 | 0 |
| `misc_structures__delay_import_count` | int64 | 0 |
| `misc_structures__delay_import_dlls__n` | int64 | 0 |
| `misc_structures__has_load_configuration` | int64 | 0 |
| `misc_structures__delay_import_dlls__longueur` | int32 | 95 399 |
| `manifest__has_manifest` | int64 | 0 |
| `manifest__requested_execution_level` | string | 75 190 |
| `manifest__ui_access` | double | 76 325 |
| `manifest__size` | int64 | 62 515 |
| `debug__has_debug` | int64 | 0 |
| `debug__count` | int64 | 0 |
| `debug__types__n` | int64 | 0 |
| `debug__pdb_path` | string | 78 339 |
| `debug__types__longueur` | int32 | 68 999 |
| `dotnet__is_dotnet` | int64 | 0 |
| `dotnet__runtime_major` | int64 | 91 208 |
| `dotnet__runtime_minor` | int64 | 91 208 |
| `dotnet__flags` | int64 | 91 208 |
| `dotnet__entrypoint_token` | int64 | 91 208 |
| `dotnet__has_strong_name` | int64 | 91 208 |
| `dotnet__il_only` | int64 | 91 208 |
| `dotnet__native_entrypoint` | int64 | 91 208 |
| `exception_dir__rva` | int64 | 0 |
| `exception_dir__size` | int64 | 0 |
| `exception_dir__runtime_function_count` | int64 | 0 |
| `tls__has_tls` | double | 0 |
| `tls__callback_count` | double | 0 |
| `tls__callbacks__n` | double | 80 473 |
| `tls__addressof_callbacks` | string | 82 303 |
| `tls__addressof_index` | string | 80 483 |
| `tls__addressof_raw_data_start` | string | 80 473 |
| `tls__addressof_raw_data_end` | string | 80 473 |
| `tls__raw_data_size` | double | 80 473 |
| `tls__sizeof_zero_fill` | double | 80 473 |
| `tls__characteristics` | double | 80 473 |
| `tls__section` | string | 80 480 |
| `tls__data_template_hex` | string | 81 711 |
| `tls__data_template_entropy` | double | 81 711 |
| `tls__callbacks__longueur` | int32 | 95 577 |
| `data_directories__n` | int64 | 0 |
| `version_info__present` | int64 | 15 814 |
| `version_info__company_name` | string | 56 803 |
| `version_info__file_description` | string | 54 688 |
| `version_info__original_filename` | string | 57 981 |
| `version_info__product_name` | string | 54 569 |
| `version_info__file_version` | string | 51 347 |
| `version_info__legal_copyright` | string | 56 393 |
| `version_info__internal_name` | string | 59 107 |
| `load_config__present` | double | 0 |
| `load_config__security_cookie` | double | 73 552 |
| `load_config__se_handler_count` | double | 73 665 |
| `load_config__guard_cf_function_count` | double | 88 536 |
| `load_config__guard_flags` | double | 88 536 |
| `digital_signature__signature_present` | int64 | 0 |
| `digital_signature__verification_flag` | string | 0 |
| `digital_signature__signature_count` | int64 | 0 |
| `digital_signature__certificates__n` | int64 | 0 |
| `dir_export_table_taille` | int64 | 0 |
| `dir_export_table_rva` | int64 | 0 |
| `dir_export_table_hors_sections` | bool | 0 |
| `dir_import_table_taille` | int64 | 0 |
| `dir_import_table_rva` | int64 | 0 |
| `dir_import_table_hors_sections` | bool | 0 |
| `dir_resource_table_taille` | int64 | 0 |
| `dir_resource_table_rva` | int64 | 0 |
| `dir_resource_table_hors_sections` | bool | 0 |
| `dir_exception_table_taille` | int64 | 0 |
| `dir_exception_table_rva` | int64 | 0 |
| `dir_exception_table_hors_sections` | bool | 0 |
| `dir_certificate_table_taille` | int64 | 0 |
| `dir_certificate_table_rva` | int64 | 0 |
| `dir_certificate_table_hors_sections` | bool | 0 |
| `dir_base_relocation_table_taille` | int64 | 0 |
| `dir_base_relocation_table_rva` | int64 | 0 |
| `dir_base_relocation_table_hors_sections` | bool | 0 |
| `dir_debug_dir_taille` | int64 | 0 |
| `dir_debug_dir_rva` | int64 | 0 |
| `dir_debug_dir_hors_sections` | bool | 0 |
| `dir_architecture_taille` | int64 | 0 |
| `dir_architecture_rva` | int64 | 0 |
| `dir_architecture_hors_sections` | bool | 0 |
| `dir_global_ptr_taille` | int64 | 0 |
| `dir_global_ptr_rva` | int64 | 0 |
| `dir_global_ptr_hors_sections` | bool | 0 |
| `dir_tls_table_taille` | int64 | 0 |
| `dir_tls_table_rva` | int64 | 0 |
| `dir_tls_table_hors_sections` | bool | 0 |
| `dir_load_config_table_taille` | int64 | 0 |
| `dir_load_config_table_rva` | int64 | 0 |
| `dir_load_config_table_hors_sections` | bool | 0 |
| `dir_bound_import_taille` | int64 | 0 |
| `dir_bound_import_rva` | int64 | 0 |
| `dir_bound_import_hors_sections` | bool | 0 |
| `dir_iat_taille` | int64 | 0 |
| `dir_iat_rva` | int64 | 0 |
| `dir_iat_hors_sections` | bool | 0 |
| `dir_delay_import_descriptor_taille` | int64 | 0 |
| `dir_delay_import_descriptor_rva` | int64 | 0 |
| `dir_delay_import_descriptor_hors_sections` | bool | 0 |
| `dir_clr_runtime_header_taille` | int64 | 0 |
| `dir_clr_runtime_header_rva` | int64 | 0 |
| `dir_clr_runtime_header_hors_sections` | bool | 0 |
| `dir_reserved_taille` | int64 | 0 |
| `dir_reserved_rva` | int64 | 0 |
| `dir_reserved_hors_sections` | bool | 0 |
| `res_type_00:id6` | int8 | 0 |
| `res_type_01:id3` | int8 | 0 |
| `res_type_02:id1` | int8 | 0 |
| `res_type_03:id2` | int8 | 0 |
| `res_type_04:id5` | int8 | 0 |
| `res_type_05:id10` | int8 | 0 |
| `res_type_06:id12` | int8 | 0 |
| `res_type_07:id14` | int8 | 0 |
| `res_type_08:id16` | int8 | 0 |
| `res_type_09:png` | int8 | 0 |
| `res_type_10:id24` | int8 | 0 |
| `res_type_11:id4` | int8 | 0 |
| `res_type_12:id9` | int8 | 0 |
| `res_type_13:afx_dialog_layout` | int8 | 0 |
| `res_type_14:clrc` | int8 | 0 |
| `res_type_15:image` | int8 | 0 |
| `res_type_16:id241` | int8 | 0 |
| `res_type_17:id23` | int8 | 0 |
| `res_type_18:id11` | int8 | 0 |
| `res_type_19:data` | int8 | 0 |
| `res_type_20:registry` | int8 | 0 |
| `res_type_21:custom` | int8 | 0 |
| `res_type_22:typelib` | int8 | 0 |
| `res_type_23:pngf` | int8 | 0 |
| `res_type_24:jpeg` | int8 | 0 |
| `res_type_25:id240` | int8 | 0 |
| `res_type_26:id384` | int8 | 0 |
| `res_type_27:id256` | int8 | 0 |
| `res_type_28:id29` | int8 | 0 |
| `res_type_29:cdrc` | int8 | 0 |
| `res_type_30:textinclude` | int8 | 0 |
| `res_type_31:w` | int8 | 0 |
| `res_type_32:avi` | int8 | 0 |
| `res_type_33:id262` | int8 | 0 |
| `res_type_34:wave` | int8 | 0 |
| `res_type_35:id3409` | int8 | 0 |
| `res_type_36:rtf` | int8 | 0 |
| `res_type_37:mui` | int8 | 0 |
| `res_type_38:id261` | int8 | 0 |
| `res_type_39:bin` | int8 | 0 |
| `res_type_40:binary` | int8 | 0 |
| `res_type_41:stringtablecustom` | int8 | 0 |
| `res_type_42:dll` | int8 | 0 |
| `res_type_43:xmlf` | int8 | 0 |
| `res_type_44:id8` | int8 | 0 |
| `res_type_45:bitmap4` | int8 | 0 |
| `res_type_46:id22` | int8 | 0 |
| `res_type_47:view` | int8 | 0 |
| `res_type_48:id43` | int8 | 0 |
| `res_type_49:id3401` | int8 | 0 |
| `res_type_50:id3400` | int8 | 0 |
| `res_type_51:style_xml` | int8 | 0 |
| `res_type_52:unicodedata` | int8 | 0 |
| `res_type_53:smnu` | int8 | 0 |
| `res_type_54:id21` | int8 | 0 |
| `res_type_55:zmnu` | int8 | 0 |
| `res_type_56:gif` | int8 | 0 |
| `res_type_57:stringres` | int8 | 0 |
| `res_type_58:id7` | int8 | 0 |
| `res_type_59:id15` | int8 | 0 |
| `res_type_60:id17` | int8 | 0 |
| `res_type_61:php` | int8 | 0 |
| `res_type_62:оолтимасч` | int8 | 0 |
| `res_type_63:xml` | int8 | 0 |
| `res_type_64:svg` | int8 | 0 |
| `res_type_65:media` | int8 | 0 |
| `res_type_66:file` | int8 | 0 |
| `res_type_67:text` | int8 | 0 |
| `res_type_68:commanddata` | int8 | 0 |
| `res_type_69:setupcommand` | int8 | 0 |
| `res_type_70:id100` | int8 | 0 |
| `res_type_71:id255` | int8 | 0 |
| `res_type_72:id259` | int8 | 0 |
| `res_type_73:rt_rcdata` | int8 | 0 |
| `res_type_74:exvw` | int8 | 0 |
| `res_type_75:curs` | int8 | 0 |
| `res_type_76:id3408` | int8 | 0 |
| `res_type_77:csr1` | int8 | 0 |
| `res_type_78:jpg` | int8 | 0 |
| `res_type_79:csr2` | int8 | 0 |
| `res_type_80:id258` | int8 | 0 |
| `res_type_81:id63` | int8 | 0 |
| `res_type_82:wevt_template` | int8 | 0 |
| `res_type_83:kunadorehumenanamovizo` | int8 | 0 |
| `res_type_84:senuzemix` | int8 | 0 |
| `res_type_85:tp5ccy30` | int8 | 0 |
| `res_type_86:iefile` | int8 | 0 |
| `res_type_87:id1000` | int8 | 0 |
| `res_type_88:psprocset` | int8 | 0 |
| `res_type_89:mofile` | int8 | 0 |
| `res_type_90:id25` | int8 | 0 |
| `res_type_91:id217` | int8 | 0 |
| `res_type_92:img` | int8 | 0 |
| `res_type_93:id30` | int8 | 0 |
| `res_type_94:cpp` | int8 | 0 |
| `res_type_95:txt` | int8 | 0 |
| `res_type_96:string` | int8 | 0 |
| `res_type_97:textfile` | int8 | 0 |
| `res_type_98:fig` | int8 | 0 |
| `res_type_99:id2110` | int8 | 0 |
| `res_type_100:skin` | int8 | 0 |
| `res_type_101:твыячйл` | int8 | 0 |
| `res_type_102:gz` | int8 | 0 |
| `res_type_103:pngi` | int8 | 0 |
| `res_type_104:ui-data` | int8 | 0 |
| `res_type_105:pngglobal` | int8 | 0 |
| `res_type_106:exe` | int8 | 0 |
| `res_type_107:tls` | int8 | 0 |
| `res_type_108:mx_xml_string` | int8 | 0 |
| `res_type_109:dat_resource_chunk` | int8 | 0 |
| `res_type_110:limitedaccessfeature` | int8 | 0 |
| `res_type_111:fcvdw34sio` | int8 | 0 |
| `res_type_112:risohtemplate` | int8 | 0 |
| `res_type_113:id998` | int8 | 0 |
| `res_type_114:1` | int8 | 0 |
| `res_type_115:id999` | int8 | 0 |
| `res_type_116:idNone` | int8 | 0 |
| `res_type_117:sicn` | int8 | 0 |
| `res_type_118:id257` | int8 | 0 |
| `res_type_119:translation` | int8 | 0 |
| `res_type_120:ьтнривчц` | int8 | 0 |
| `res_type_121:uifile` | int8 | 0 |
| `res_type_122:zukamajimero` | int8 | 0 |
| `res_type_123:mjuygvdsqu` | int8 | 0 |
| `res_type_124:r` | int8 | 0 |
| `res_type_125:id260` | int8 | 0 |
| `res_type_126:id101` | int8 | 0 |
| `res_type_127:id500` | int8 | 0 |
| `res_type_128:rt_xaml` | int8 | 0 |
| `res_type_129:host` | int8 | 0 |
| `res_type_130:exefile` | int8 | 0 |
| `res_type_131:блдвсуцый1г` | int8 | 0 |
| `res_type_132:lrcdata` | int8 | 0 |
| `res_type_133:id28` | int8 | 0 |
| `res_type_134:ьлшшгриав` | int8 | 0 |
| `res_type_135:b` | int8 | 0 |
| `res_type_136:mimela` | int8 | 0 |
| `res_type_137:chunk_res_data` | int8 | 0 |
| `res_type_138:codefragment` | int8 | 0 |
| `res_type_139:h97v6m29` | int8 | 0 |
| `res_type_140:glyphdata` | int8 | 0 |
| `res_type_141:wociyiyajetafo` | int8 | 0 |
| `res_type_142:rcdata` | int8 | 0 |
| `res_type_143:layout` | int8 | 0 |
| `res_type_144:dds_libshape` | int8 | 0 |
| `res_type_145:jsondata` | int8 | 0 |
| `res_type_146:script` | int8 | 0 |
| `res_type_147:binres` | int8 | 0 |
| `res_type_148:wm_dsp` | int8 | 0 |
| `res_type_149:шшшо` | int8 | 0 |
| `res_type_150:mad` | int8 | 0 |
| `res_type_151:code` | int8 | 0 |
| `res_type_152:id1234` | int8 | 0 |
| `res_type_153:id1337` | int8 | 0 |
| `res_type_154:одддиткацы` | int8 | 0 |
| `res_type_155:driver` | int8 | 0 |
| `res_type_156:archive_7z` | int8 | 0 |
| `res_type_157:qqmusic` | int8 | 0 |
| `res_n` | int32 | 17 563 |
| `res_entropie_max` | float | 17 563 |
| `res_entropie_moyenne` | float | 17 563 |
| `res_taille_totale` | int64 | 17 538 |
| `res_taille_max` | int64 | 17 538 |
| `res_n_types` | int32 | 17 538 |
| `cert_emetteur_00:c=us, st=washington, l=redmond, o=micros` | int8 | 0 |
| `cert_emetteur_01:c=gb, st=greater manchester, l=salford, ` | int8 | 0 |
| `cert_emetteur_02:c=za, st=western cape, l=durbanville, o=` | int8 | 0 |
| `cert_emetteur_03:c=us, o=digicert inc, ou=www.digicert.co` | int8 | 0 |
| `cert_emetteur_04:c=us, o=digicert inc, ou=www.digicert.co` | int8 | 0 |
| `cert_emetteur_05:c=us, o=verisign\, inc., ou=verisign tru` | int8 | 0 |
| `cert_emetteur_06:c=us, o=verisign\, inc., cn=verisign tim` | int8 | 0 |
| `cert_emetteur_07:c=us, o=digicert\, inc., cn=digicert tru` | int8 | 0 |
| `cert_emetteur_08:c=us, o=verisign\, inc., ou=verisign tru` | int8 | 0 |
| `cert_emetteur_09:dc=com, dc=microsoft, cn=microsoft root ` | int8 | 0 |
| `cert_emetteur_10:ou=copyright (c) 1997 microsoft corp., o` | int8 | 0 |
| `cert_emetteur_11:c=us, o=symantec corporation, cn=symante` | int8 | 0 |
| `cert_emetteur_12:c=us, st=new jersey, l=jersey city, o=th` | int8 | 0 |
| `cert_emetteur_13:c=us, o=thawte\, inc., ou=certification ` | int8 | 0 |
| `cert_emetteur_14:c=gb, st=greater manchester, l=salford, ` | int8 | 0 |
| `cert_emetteur_15:c=gb, o=sectigo limited, cn=sectigo publ` | int8 | 0 |
| `cert_emetteur_16:c=us, o=verisign\, inc., ou=class 3 publ` | int8 | 0 |
| `cert_emetteur_17:c=gb, o=sectigo limited, cn=sectigo publ` | int8 | 0 |
| `cert_emetteur_18:c=us, o=digicert inc, ou=www.digicert.co` | int8 | 0 |
| `cert_emetteur_19:c=pl, o=unizeto technologies s.a., ou=ce` | int8 | 0 |
| `cert_emetteur_20:c=us, o=digicert inc, ou=www.digicert.co` | int8 | 0 |
| `cert_emetteur_21:c=us, st=ut, l=salt lake city, o=the use` | int8 | 0 |
| `cert_emetteur_22:c=za, st=western cape, l=cape town, o=th` | int8 | 0 |
| `cert_emetteur_23:c=us, o=digicert\, inc., cn=digicert tru` | int8 | 0 |
| `cert_emetteur_24:c=us, o=thawte\, inc., cn=thawte code si` | int8 | 0 |
| `cert_emetteur_25:c=us, o=entrust\, inc., ou=see www.entru` | int8 | 0 |
| `cert_emetteur_26:c=us, o=symantec corporation, ou=symante` | int8 | 0 |
| `cert_emetteur_27:c=be, o=globalsign nv-sa, cn=globalsign ` | int8 | 0 |
| `cert_emetteur_28:c=be, o=globalsign nv-sa, ou=root ca, cn` | int8 | 0 |
| `cert_emetteur_29:c=us, o=microsoft corporation, cn=micros` | int8 | 0 |
| `cert_emetteur_30:c=us, o=thawte\, inc., cn=thawte sha256 ` | int8 | 0 |
| `cert_emetteur_31:c=us, o=digicert\, inc., cn=digicert tru` | int8 | 0 |
| `cert_emetteur_32:c=us, o=digicert inc, ou=www.digicert.co` | int8 | 0 |
| `cert_emetteur_33:ou=globalsign root ca - r3, o=globalsign` | int8 | 0 |
| `cert_emetteur_34:c=za, o=thawte consulting (pty) ltd., cn` | int8 | 0 |
| `cert_emetteur_35:c=us, st=texas, l=houston, o=ssl corpora` | int8 | 0 |
| `cert_emetteur_36:c=be, o=globalsign nv-sa, cn=globalsign ` | int8 | 0 |
| `cert_emetteur_37:c=us, o=entrust\, inc., cn=entrust code ` | int8 | 0 |
| `cert_emetteur_38:c=us, o=entrust\, inc., cn=entrust exten` | int8 | 0 |
| `cert_emetteur_39:c=pl, o=asseco data systems s.a., cn=cer` | int8 | 0 |
| `cert_emetteur_40:o=verisign trust network, ou=verisign\, ` | int8 | 0 |
| `cert_emetteur_41:c=us, st=washington, l=redmond, o=micros` | int8 | 0 |
| `cert_emetteur_42:c=se, o=addtrust ab, ou=addtrust externa` | int8 | 0 |
| `cert_emetteur_43:c=us, o=microsoft corporation, cn=micros` | int8 | 0 |
| `cert_emetteur_44:c=us, o=microsoft corporation, cn=micros` | int8 | 0 |
| `cert_emetteur_45:c=be, o=globalsign nv-sa, cn=globalsign ` | int8 | 0 |
| `cert_emetteur_46:c=us, st=texas, l=houston, o=ssl corp, c` | int8 | 0 |
| `cert_emetteur_47:c=be, o=globalsign nv-sa, cn=globalsign ` | int8 | 0 |
| `cert_emetteur_48:c=be, o=globalsign nv-sa, ou=objectsign ` | int8 | 0 |
| `cert_emetteur_49:c=be, o=globalsign nv-sa, ou=primary obj` | int8 | 0 |
| `cert_emetteur_50:c=gb, o=sectigo limited, cn=sectigo publ` | int8 | 0 |
| `cert_emetteur_51:c=gb, o=sectigo limited, cn=sectigo publ` | int8 | 0 |
| `cert_emetteur_52:c=us, o=gte corporation, ou=gte cybertru` | int8 | 0 |
| `cert_emetteur_53:c=us, o=microsoft corporation, cn=micros` | int8 | 0 |
| `cert_emetteur_54:c=pl, o=asseco data systems s.a., cn=cer` | int8 | 0 |
| `cert_emetteur_55:c=us, o=microsoft corporation, cn=micros` | int8 | 0 |
| `cert_emetteur_56:cn=we1` | int8 | 0 |
| `cert_emetteur_57:c=gb, o=sectigo limited, cn=sectigo publ` | int8 | 0 |
| `cert_emetteur_58:c=us, o=microsoft corporation, cn=micros` | int8 | 0 |
| `cert_emetteur_59:c=be, o=globalsign nv-sa, cn=globalsign ` | int8 | 0 |
| `cert_algo:1.2.840.10045.4.3.2` | int8 | 0 |
| `cert_algo:1.2.840.10045.4.3.3` | int8 | 0 |
| `cert_algo:1.2.840.10045.4.3.4` | int8 | 0 |
| `cert_algo:1.2.840.113549.1.1.11` | int8 | 0 |
| `cert_algo:1.2.840.113549.1.1.12` | int8 | 0 |
| `cert_algo:1.2.840.113549.1.1.13` | int8 | 0 |
| `cert_algo:1.2.840.113549.1.1.4` | int8 | 0 |
| `cert_algo:1.2.840.113549.1.1.5` | int8 | 0 |
| `cert_algo:1.3.14.3.2.29` | int8 | 0 |
| `cert_n` | int16 | 85 632 |
| `cert_n_autorites` | int16 | 85 632 |
| `cert_duree_max_annees` | int16 | 85 632 |
| `cert_duree_min_annees` | int16 | 85 632 |

## `content.parquet`

Byte histograms, entropy, strings.

- rows: 100 909
- columns: 2 372
- `str:` columns: 1 820 (string observed in the file, one column per value)

| Column | Type | Nulls |
|---|---|---|
| `byte_features__file_entropy` | double | 0 |
| `byte_features__byte_histogram_256__000` | float | 0 |
| `byte_features__byte_histogram_256__001` | float | 0 |
| `byte_features__byte_histogram_256__002` | float | 0 |
| `byte_features__byte_histogram_256__003` | float | 0 |
| `byte_features__byte_histogram_256__004` | float | 0 |
| `byte_features__byte_histogram_256__005` | float | 0 |
| `byte_features__byte_histogram_256__006` | float | 0 |
| `byte_features__byte_histogram_256__007` | float | 0 |
| `byte_features__byte_histogram_256__008` | float | 0 |
| `byte_features__byte_histogram_256__009` | float | 0 |
| `byte_features__byte_histogram_256__010` | float | 0 |
| `byte_features__byte_histogram_256__011` | float | 0 |
| `byte_features__byte_histogram_256__012` | float | 0 |
| `byte_features__byte_histogram_256__013` | float | 0 |
| `byte_features__byte_histogram_256__014` | float | 0 |
| `byte_features__byte_histogram_256__015` | float | 0 |
| `byte_features__byte_histogram_256__016` | float | 0 |
| `byte_features__byte_histogram_256__017` | float | 0 |
| `byte_features__byte_histogram_256__018` | float | 0 |
| `byte_features__byte_histogram_256__019` | float | 0 |
| `byte_features__byte_histogram_256__020` | float | 0 |
| `byte_features__byte_histogram_256__021` | float | 0 |
| `byte_features__byte_histogram_256__022` | float | 0 |
| `byte_features__byte_histogram_256__023` | float | 0 |
| `byte_features__byte_histogram_256__024` | float | 0 |
| `byte_features__byte_histogram_256__025` | float | 0 |
| `byte_features__byte_histogram_256__026` | float | 0 |
| `byte_features__byte_histogram_256__027` | float | 0 |
| `byte_features__byte_histogram_256__028` | float | 0 |
| `byte_features__byte_histogram_256__029` | float | 0 |
| `byte_features__byte_histogram_256__030` | float | 0 |
| `byte_features__byte_histogram_256__031` | float | 0 |
| `byte_features__byte_histogram_256__032` | float | 0 |
| `byte_features__byte_histogram_256__033` | float | 0 |
| `byte_features__byte_histogram_256__034` | float | 0 |
| `byte_features__byte_histogram_256__035` | float | 0 |
| `byte_features__byte_histogram_256__036` | float | 0 |
| `byte_features__byte_histogram_256__037` | float | 0 |
| `byte_features__byte_histogram_256__038` | float | 0 |
| `byte_features__byte_histogram_256__039` | float | 0 |
| `byte_features__byte_histogram_256__040` | float | 0 |
| `byte_features__byte_histogram_256__041` | float | 0 |
| `byte_features__byte_histogram_256__042` | float | 0 |
| `byte_features__byte_histogram_256__043` | float | 0 |
| `byte_features__byte_histogram_256__044` | float | 0 |
| `byte_features__byte_histogram_256__045` | float | 0 |
| `byte_features__byte_histogram_256__046` | float | 0 |
| `byte_features__byte_histogram_256__047` | float | 0 |
| `byte_features__byte_histogram_256__048` | float | 0 |
| `byte_features__byte_histogram_256__049` | float | 0 |
| `byte_features__byte_histogram_256__050` | float | 0 |
| `byte_features__byte_histogram_256__051` | float | 0 |
| `byte_features__byte_histogram_256__052` | float | 0 |
| `byte_features__byte_histogram_256__053` | float | 0 |
| `byte_features__byte_histogram_256__054` | float | 0 |
| `byte_features__byte_histogram_256__055` | float | 0 |
| `byte_features__byte_histogram_256__056` | float | 0 |
| `byte_features__byte_histogram_256__057` | float | 0 |
| `byte_features__byte_histogram_256__058` | float | 0 |
| `byte_features__byte_histogram_256__059` | float | 0 |
| `byte_features__byte_histogram_256__060` | float | 0 |
| `byte_features__byte_histogram_256__061` | float | 0 |
| `byte_features__byte_histogram_256__062` | float | 0 |
| `byte_features__byte_histogram_256__063` | float | 0 |
| `byte_features__byte_histogram_256__064` | float | 0 |
| `byte_features__byte_histogram_256__065` | float | 0 |
| `byte_features__byte_histogram_256__066` | float | 0 |
| `byte_features__byte_histogram_256__067` | float | 0 |
| `byte_features__byte_histogram_256__068` | float | 0 |
| `byte_features__byte_histogram_256__069` | float | 0 |
| `byte_features__byte_histogram_256__070` | float | 0 |
| `byte_features__byte_histogram_256__071` | float | 0 |
| `byte_features__byte_histogram_256__072` | float | 0 |
| `byte_features__byte_histogram_256__073` | float | 0 |
| `byte_features__byte_histogram_256__074` | float | 0 |
| `byte_features__byte_histogram_256__075` | float | 0 |
| `byte_features__byte_histogram_256__076` | float | 0 |
| `byte_features__byte_histogram_256__077` | float | 0 |
| `byte_features__byte_histogram_256__078` | float | 0 |
| `byte_features__byte_histogram_256__079` | float | 0 |
| `byte_features__byte_histogram_256__080` | float | 0 |
| `byte_features__byte_histogram_256__081` | float | 0 |
| `byte_features__byte_histogram_256__082` | float | 0 |
| `byte_features__byte_histogram_256__083` | float | 0 |
| `byte_features__byte_histogram_256__084` | float | 0 |
| `byte_features__byte_histogram_256__085` | float | 0 |
| `byte_features__byte_histogram_256__086` | float | 0 |
| `byte_features__byte_histogram_256__087` | float | 0 |
| `byte_features__byte_histogram_256__088` | float | 0 |
| `byte_features__byte_histogram_256__089` | float | 0 |
| `byte_features__byte_histogram_256__090` | float | 0 |
| `byte_features__byte_histogram_256__091` | float | 0 |
| `byte_features__byte_histogram_256__092` | float | 0 |
| `byte_features__byte_histogram_256__093` | float | 0 |
| `byte_features__byte_histogram_256__094` | float | 0 |
| `byte_features__byte_histogram_256__095` | float | 0 |
| `byte_features__byte_histogram_256__096` | float | 0 |
| `byte_features__byte_histogram_256__097` | float | 0 |
| `byte_features__byte_histogram_256__098` | float | 0 |
| `byte_features__byte_histogram_256__099` | float | 0 |
| `byte_features__byte_histogram_256__100` | float | 0 |
| `byte_features__byte_histogram_256__101` | float | 0 |
| `byte_features__byte_histogram_256__102` | float | 0 |
| `byte_features__byte_histogram_256__103` | float | 0 |
| `byte_features__byte_histogram_256__104` | float | 0 |
| `byte_features__byte_histogram_256__105` | float | 0 |
| `byte_features__byte_histogram_256__106` | float | 0 |
| `byte_features__byte_histogram_256__107` | float | 0 |
| `byte_features__byte_histogram_256__108` | float | 0 |
| `byte_features__byte_histogram_256__109` | float | 0 |
| `byte_features__byte_histogram_256__110` | float | 0 |
| `byte_features__byte_histogram_256__111` | float | 0 |
| `byte_features__byte_histogram_256__112` | float | 0 |
| `byte_features__byte_histogram_256__113` | float | 0 |
| `byte_features__byte_histogram_256__114` | float | 0 |
| `byte_features__byte_histogram_256__115` | float | 0 |
| `byte_features__byte_histogram_256__116` | float | 0 |
| `byte_features__byte_histogram_256__117` | float | 0 |
| `byte_features__byte_histogram_256__118` | float | 0 |
| `byte_features__byte_histogram_256__119` | float | 0 |
| `byte_features__byte_histogram_256__120` | float | 0 |
| `byte_features__byte_histogram_256__121` | float | 0 |
| `byte_features__byte_histogram_256__122` | float | 0 |
| `byte_features__byte_histogram_256__123` | float | 0 |
| `byte_features__byte_histogram_256__124` | float | 0 |
| `byte_features__byte_histogram_256__125` | float | 0 |
| `byte_features__byte_histogram_256__126` | float | 0 |
| `byte_features__byte_histogram_256__127` | float | 0 |
| `byte_features__byte_histogram_256__128` | float | 0 |
| `byte_features__byte_histogram_256__129` | float | 0 |
| `byte_features__byte_histogram_256__130` | float | 0 |
| `byte_features__byte_histogram_256__131` | float | 0 |
| `byte_features__byte_histogram_256__132` | float | 0 |
| `byte_features__byte_histogram_256__133` | float | 0 |
| `byte_features__byte_histogram_256__134` | float | 0 |
| `byte_features__byte_histogram_256__135` | float | 0 |
| `byte_features__byte_histogram_256__136` | float | 0 |
| `byte_features__byte_histogram_256__137` | float | 0 |
| `byte_features__byte_histogram_256__138` | float | 0 |
| `byte_features__byte_histogram_256__139` | float | 0 |
| `byte_features__byte_histogram_256__140` | float | 0 |
| `byte_features__byte_histogram_256__141` | float | 0 |
| `byte_features__byte_histogram_256__142` | float | 0 |
| `byte_features__byte_histogram_256__143` | float | 0 |
| `byte_features__byte_histogram_256__144` | float | 0 |
| `byte_features__byte_histogram_256__145` | float | 0 |
| `byte_features__byte_histogram_256__146` | float | 0 |
| `byte_features__byte_histogram_256__147` | float | 0 |
| `byte_features__byte_histogram_256__148` | float | 0 |
| `byte_features__byte_histogram_256__149` | float | 0 |
| `byte_features__byte_histogram_256__150` | float | 0 |
| `byte_features__byte_histogram_256__151` | float | 0 |
| `byte_features__byte_histogram_256__152` | float | 0 |
| `byte_features__byte_histogram_256__153` | float | 0 |
| `byte_features__byte_histogram_256__154` | float | 0 |
| `byte_features__byte_histogram_256__155` | float | 0 |
| `byte_features__byte_histogram_256__156` | float | 0 |
| `byte_features__byte_histogram_256__157` | float | 0 |
| `byte_features__byte_histogram_256__158` | float | 0 |
| `byte_features__byte_histogram_256__159` | float | 0 |
| `byte_features__byte_histogram_256__160` | float | 0 |
| `byte_features__byte_histogram_256__161` | float | 0 |
| `byte_features__byte_histogram_256__162` | float | 0 |
| `byte_features__byte_histogram_256__163` | float | 0 |
| `byte_features__byte_histogram_256__164` | float | 0 |
| `byte_features__byte_histogram_256__165` | float | 0 |
| `byte_features__byte_histogram_256__166` | float | 0 |
| `byte_features__byte_histogram_256__167` | float | 0 |
| `byte_features__byte_histogram_256__168` | float | 0 |
| `byte_features__byte_histogram_256__169` | float | 0 |
| `byte_features__byte_histogram_256__170` | float | 0 |
| `byte_features__byte_histogram_256__171` | float | 0 |
| `byte_features__byte_histogram_256__172` | float | 0 |
| `byte_features__byte_histogram_256__173` | float | 0 |
| `byte_features__byte_histogram_256__174` | float | 0 |
| `byte_features__byte_histogram_256__175` | float | 0 |
| `byte_features__byte_histogram_256__176` | float | 0 |
| `byte_features__byte_histogram_256__177` | float | 0 |
| `byte_features__byte_histogram_256__178` | float | 0 |
| `byte_features__byte_histogram_256__179` | float | 0 |
| `byte_features__byte_histogram_256__180` | float | 0 |
| `byte_features__byte_histogram_256__181` | float | 0 |
| `byte_features__byte_histogram_256__182` | float | 0 |
| `byte_features__byte_histogram_256__183` | float | 0 |
| `byte_features__byte_histogram_256__184` | float | 0 |
| `byte_features__byte_histogram_256__185` | float | 0 |
| `byte_features__byte_histogram_256__186` | float | 0 |
| `byte_features__byte_histogram_256__187` | float | 0 |
| `byte_features__byte_histogram_256__188` | float | 0 |
| `byte_features__byte_histogram_256__189` | float | 0 |
| `byte_features__byte_histogram_256__190` | float | 0 |
| `byte_features__byte_histogram_256__191` | float | 0 |
| `byte_features__byte_histogram_256__192` | float | 0 |
| `byte_features__byte_histogram_256__193` | float | 0 |
| `byte_features__byte_histogram_256__194` | float | 0 |
| `byte_features__byte_histogram_256__195` | float | 0 |
| `byte_features__byte_histogram_256__196` | float | 0 |
| `byte_features__byte_histogram_256__197` | float | 0 |
| `byte_features__byte_histogram_256__198` | float | 0 |
| `byte_features__byte_histogram_256__199` | float | 0 |
| `byte_features__byte_histogram_256__200` | float | 0 |
| `byte_features__byte_histogram_256__201` | float | 0 |
| `byte_features__byte_histogram_256__202` | float | 0 |
| `byte_features__byte_histogram_256__203` | float | 0 |
| `byte_features__byte_histogram_256__204` | float | 0 |
| `byte_features__byte_histogram_256__205` | float | 0 |
| `byte_features__byte_histogram_256__206` | float | 0 |
| `byte_features__byte_histogram_256__207` | float | 0 |
| `byte_features__byte_histogram_256__208` | float | 0 |
| `byte_features__byte_histogram_256__209` | float | 0 |
| `byte_features__byte_histogram_256__210` | float | 0 |
| `byte_features__byte_histogram_256__211` | float | 0 |
| `byte_features__byte_histogram_256__212` | float | 0 |
| `byte_features__byte_histogram_256__213` | float | 0 |
| `byte_features__byte_histogram_256__214` | float | 0 |
| `byte_features__byte_histogram_256__215` | float | 0 |
| `byte_features__byte_histogram_256__216` | float | 0 |
| `byte_features__byte_histogram_256__217` | float | 0 |
| `byte_features__byte_histogram_256__218` | float | 0 |
| `byte_features__byte_histogram_256__219` | float | 0 |
| `byte_features__byte_histogram_256__220` | float | 0 |
| `byte_features__byte_histogram_256__221` | float | 0 |
| `byte_features__byte_histogram_256__222` | float | 0 |
| `byte_features__byte_histogram_256__223` | float | 0 |
| `byte_features__byte_histogram_256__224` | float | 0 |
| `byte_features__byte_histogram_256__225` | float | 0 |
| `byte_features__byte_histogram_256__226` | float | 0 |
| `byte_features__byte_histogram_256__227` | float | 0 |
| `byte_features__byte_histogram_256__228` | float | 0 |
| `byte_features__byte_histogram_256__229` | float | 0 |
| `byte_features__byte_histogram_256__230` | float | 0 |
| `byte_features__byte_histogram_256__231` | float | 0 |
| `byte_features__byte_histogram_256__232` | float | 0 |
| `byte_features__byte_histogram_256__233` | float | 0 |
| `byte_features__byte_histogram_256__234` | float | 0 |
| `byte_features__byte_histogram_256__235` | float | 0 |
| `byte_features__byte_histogram_256__236` | float | 0 |
| `byte_features__byte_histogram_256__237` | float | 0 |
| `byte_features__byte_histogram_256__238` | float | 0 |
| `byte_features__byte_histogram_256__239` | float | 0 |
| `byte_features__byte_histogram_256__240` | float | 0 |
| `byte_features__byte_histogram_256__241` | float | 0 |
| `byte_features__byte_histogram_256__242` | float | 0 |
| `byte_features__byte_histogram_256__243` | float | 0 |
| `byte_features__byte_histogram_256__244` | float | 0 |
| `byte_features__byte_histogram_256__245` | float | 0 |
| `byte_features__byte_histogram_256__246` | float | 0 |
| `byte_features__byte_histogram_256__247` | float | 0 |
| `byte_features__byte_histogram_256__248` | float | 0 |
| `byte_features__byte_histogram_256__249` | float | 0 |
| `byte_features__byte_histogram_256__250` | float | 0 |
| `byte_features__byte_histogram_256__251` | float | 0 |
| `byte_features__byte_histogram_256__252` | float | 0 |
| `byte_features__byte_histogram_256__253` | float | 0 |
| `byte_features__byte_histogram_256__254` | float | 0 |
| `byte_features__byte_histogram_256__255` | float | 0 |
| `byte_features__byte_histogram_256__n` | int64 | 0 |
| `byte_features__byte_entropy_histogram_256__000` | float | 0 |
| `byte_features__byte_entropy_histogram_256__001` | float | 0 |
| `byte_features__byte_entropy_histogram_256__002` | float | 0 |
| `byte_features__byte_entropy_histogram_256__003` | float | 0 |
| `byte_features__byte_entropy_histogram_256__004` | float | 0 |
| `byte_features__byte_entropy_histogram_256__005` | float | 0 |
| `byte_features__byte_entropy_histogram_256__006` | float | 0 |
| `byte_features__byte_entropy_histogram_256__007` | float | 0 |
| `byte_features__byte_entropy_histogram_256__008` | float | 0 |
| `byte_features__byte_entropy_histogram_256__009` | float | 0 |
| `byte_features__byte_entropy_histogram_256__010` | float | 0 |
| `byte_features__byte_entropy_histogram_256__011` | float | 0 |
| `byte_features__byte_entropy_histogram_256__012` | float | 0 |
| `byte_features__byte_entropy_histogram_256__013` | float | 0 |
| `byte_features__byte_entropy_histogram_256__014` | float | 0 |
| `byte_features__byte_entropy_histogram_256__015` | float | 0 |
| `byte_features__byte_entropy_histogram_256__016` | float | 0 |
| `byte_features__byte_entropy_histogram_256__017` | float | 0 |
| `byte_features__byte_entropy_histogram_256__018` | float | 0 |
| `byte_features__byte_entropy_histogram_256__019` | float | 0 |
| `byte_features__byte_entropy_histogram_256__020` | float | 0 |
| `byte_features__byte_entropy_histogram_256__021` | float | 0 |
| `byte_features__byte_entropy_histogram_256__022` | float | 0 |
| `byte_features__byte_entropy_histogram_256__023` | float | 0 |
| `byte_features__byte_entropy_histogram_256__024` | float | 0 |
| `byte_features__byte_entropy_histogram_256__025` | float | 0 |
| `byte_features__byte_entropy_histogram_256__026` | float | 0 |
| `byte_features__byte_entropy_histogram_256__027` | float | 0 |
| `byte_features__byte_entropy_histogram_256__028` | float | 0 |
| `byte_features__byte_entropy_histogram_256__029` | float | 0 |
| `byte_features__byte_entropy_histogram_256__030` | float | 0 |
| `byte_features__byte_entropy_histogram_256__031` | float | 0 |
| `byte_features__byte_entropy_histogram_256__032` | float | 0 |
| `byte_features__byte_entropy_histogram_256__033` | float | 0 |
| `byte_features__byte_entropy_histogram_256__034` | float | 0 |
| `byte_features__byte_entropy_histogram_256__035` | float | 0 |
| `byte_features__byte_entropy_histogram_256__036` | float | 0 |
| `byte_features__byte_entropy_histogram_256__037` | float | 0 |
| `byte_features__byte_entropy_histogram_256__038` | float | 0 |
| `byte_features__byte_entropy_histogram_256__039` | float | 0 |
| `byte_features__byte_entropy_histogram_256__040` | float | 0 |
| `byte_features__byte_entropy_histogram_256__041` | float | 0 |
| `byte_features__byte_entropy_histogram_256__042` | float | 0 |
| `byte_features__byte_entropy_histogram_256__043` | float | 0 |
| `byte_features__byte_entropy_histogram_256__044` | float | 0 |
| `byte_features__byte_entropy_histogram_256__045` | float | 0 |
| `byte_features__byte_entropy_histogram_256__046` | float | 0 |
| `byte_features__byte_entropy_histogram_256__047` | float | 0 |
| `byte_features__byte_entropy_histogram_256__048` | float | 0 |
| `byte_features__byte_entropy_histogram_256__049` | float | 0 |
| `byte_features__byte_entropy_histogram_256__050` | float | 0 |
| `byte_features__byte_entropy_histogram_256__051` | float | 0 |
| `byte_features__byte_entropy_histogram_256__052` | float | 0 |
| `byte_features__byte_entropy_histogram_256__053` | float | 0 |
| `byte_features__byte_entropy_histogram_256__054` | float | 0 |
| `byte_features__byte_entropy_histogram_256__055` | float | 0 |
| `byte_features__byte_entropy_histogram_256__056` | float | 0 |
| `byte_features__byte_entropy_histogram_256__057` | float | 0 |
| `byte_features__byte_entropy_histogram_256__058` | float | 0 |
| `byte_features__byte_entropy_histogram_256__059` | float | 0 |
| `byte_features__byte_entropy_histogram_256__060` | float | 0 |
| `byte_features__byte_entropy_histogram_256__061` | float | 0 |
| `byte_features__byte_entropy_histogram_256__062` | float | 0 |
| `byte_features__byte_entropy_histogram_256__063` | float | 0 |
| `byte_features__byte_entropy_histogram_256__064` | float | 0 |
| `byte_features__byte_entropy_histogram_256__065` | float | 0 |
| `byte_features__byte_entropy_histogram_256__066` | float | 0 |
| `byte_features__byte_entropy_histogram_256__067` | float | 0 |
| `byte_features__byte_entropy_histogram_256__068` | float | 0 |
| `byte_features__byte_entropy_histogram_256__069` | float | 0 |
| `byte_features__byte_entropy_histogram_256__070` | float | 0 |
| `byte_features__byte_entropy_histogram_256__071` | float | 0 |
| `byte_features__byte_entropy_histogram_256__072` | float | 0 |
| `byte_features__byte_entropy_histogram_256__073` | float | 0 |
| `byte_features__byte_entropy_histogram_256__074` | float | 0 |
| `byte_features__byte_entropy_histogram_256__075` | float | 0 |
| `byte_features__byte_entropy_histogram_256__076` | float | 0 |
| `byte_features__byte_entropy_histogram_256__077` | float | 0 |
| `byte_features__byte_entropy_histogram_256__078` | float | 0 |
| `byte_features__byte_entropy_histogram_256__079` | float | 0 |
| `byte_features__byte_entropy_histogram_256__080` | float | 0 |
| `byte_features__byte_entropy_histogram_256__081` | float | 0 |
| `byte_features__byte_entropy_histogram_256__082` | float | 0 |
| `byte_features__byte_entropy_histogram_256__083` | float | 0 |
| `byte_features__byte_entropy_histogram_256__084` | float | 0 |
| `byte_features__byte_entropy_histogram_256__085` | float | 0 |
| `byte_features__byte_entropy_histogram_256__086` | float | 0 |
| `byte_features__byte_entropy_histogram_256__087` | float | 0 |
| `byte_features__byte_entropy_histogram_256__088` | float | 0 |
| `byte_features__byte_entropy_histogram_256__089` | float | 0 |
| `byte_features__byte_entropy_histogram_256__090` | float | 0 |
| `byte_features__byte_entropy_histogram_256__091` | float | 0 |
| `byte_features__byte_entropy_histogram_256__092` | float | 0 |
| `byte_features__byte_entropy_histogram_256__093` | float | 0 |
| `byte_features__byte_entropy_histogram_256__094` | float | 0 |
| `byte_features__byte_entropy_histogram_256__095` | float | 0 |
| `byte_features__byte_entropy_histogram_256__096` | float | 0 |
| `byte_features__byte_entropy_histogram_256__097` | float | 0 |
| `byte_features__byte_entropy_histogram_256__098` | float | 0 |
| `byte_features__byte_entropy_histogram_256__099` | float | 0 |
| `byte_features__byte_entropy_histogram_256__100` | float | 0 |
| `byte_features__byte_entropy_histogram_256__101` | float | 0 |
| `byte_features__byte_entropy_histogram_256__102` | float | 0 |
| `byte_features__byte_entropy_histogram_256__103` | float | 0 |
| `byte_features__byte_entropy_histogram_256__104` | float | 0 |
| `byte_features__byte_entropy_histogram_256__105` | float | 0 |
| `byte_features__byte_entropy_histogram_256__106` | float | 0 |
| `byte_features__byte_entropy_histogram_256__107` | float | 0 |
| `byte_features__byte_entropy_histogram_256__108` | float | 0 |
| `byte_features__byte_entropy_histogram_256__109` | float | 0 |
| `byte_features__byte_entropy_histogram_256__110` | float | 0 |
| `byte_features__byte_entropy_histogram_256__111` | float | 0 |
| `byte_features__byte_entropy_histogram_256__112` | float | 0 |
| `byte_features__byte_entropy_histogram_256__113` | float | 0 |
| `byte_features__byte_entropy_histogram_256__114` | float | 0 |
| `byte_features__byte_entropy_histogram_256__115` | float | 0 |
| `byte_features__byte_entropy_histogram_256__116` | float | 0 |
| `byte_features__byte_entropy_histogram_256__117` | float | 0 |
| `byte_features__byte_entropy_histogram_256__118` | float | 0 |
| `byte_features__byte_entropy_histogram_256__119` | float | 0 |
| `byte_features__byte_entropy_histogram_256__120` | float | 0 |
| `byte_features__byte_entropy_histogram_256__121` | float | 0 |
| `byte_features__byte_entropy_histogram_256__122` | float | 0 |
| `byte_features__byte_entropy_histogram_256__123` | float | 0 |
| `byte_features__byte_entropy_histogram_256__124` | float | 0 |
| `byte_features__byte_entropy_histogram_256__125` | float | 0 |
| `byte_features__byte_entropy_histogram_256__126` | float | 0 |
| `byte_features__byte_entropy_histogram_256__127` | float | 0 |
| `byte_features__byte_entropy_histogram_256__128` | float | 0 |
| `byte_features__byte_entropy_histogram_256__129` | float | 0 |
| `byte_features__byte_entropy_histogram_256__130` | float | 0 |
| `byte_features__byte_entropy_histogram_256__131` | float | 0 |
| `byte_features__byte_entropy_histogram_256__132` | float | 0 |
| `byte_features__byte_entropy_histogram_256__133` | float | 0 |
| `byte_features__byte_entropy_histogram_256__134` | float | 0 |
| `byte_features__byte_entropy_histogram_256__135` | float | 0 |
| `byte_features__byte_entropy_histogram_256__136` | float | 0 |
| `byte_features__byte_entropy_histogram_256__137` | float | 0 |
| `byte_features__byte_entropy_histogram_256__138` | float | 0 |
| `byte_features__byte_entropy_histogram_256__139` | float | 0 |
| `byte_features__byte_entropy_histogram_256__140` | float | 0 |
| `byte_features__byte_entropy_histogram_256__141` | float | 0 |
| `byte_features__byte_entropy_histogram_256__142` | float | 0 |
| `byte_features__byte_entropy_histogram_256__143` | float | 0 |
| `byte_features__byte_entropy_histogram_256__144` | float | 0 |
| `byte_features__byte_entropy_histogram_256__145` | float | 0 |
| `byte_features__byte_entropy_histogram_256__146` | float | 0 |
| `byte_features__byte_entropy_histogram_256__147` | float | 0 |
| `byte_features__byte_entropy_histogram_256__148` | float | 0 |
| `byte_features__byte_entropy_histogram_256__149` | float | 0 |
| `byte_features__byte_entropy_histogram_256__150` | float | 0 |
| `byte_features__byte_entropy_histogram_256__151` | float | 0 |
| `byte_features__byte_entropy_histogram_256__152` | float | 0 |
| `byte_features__byte_entropy_histogram_256__153` | float | 0 |
| `byte_features__byte_entropy_histogram_256__154` | float | 0 |
| `byte_features__byte_entropy_histogram_256__155` | float | 0 |
| `byte_features__byte_entropy_histogram_256__156` | float | 0 |
| `byte_features__byte_entropy_histogram_256__157` | float | 0 |
| `byte_features__byte_entropy_histogram_256__158` | float | 0 |
| `byte_features__byte_entropy_histogram_256__159` | float | 0 |
| `byte_features__byte_entropy_histogram_256__160` | float | 0 |
| `byte_features__byte_entropy_histogram_256__161` | float | 0 |
| `byte_features__byte_entropy_histogram_256__162` | float | 0 |
| `byte_features__byte_entropy_histogram_256__163` | float | 0 |
| `byte_features__byte_entropy_histogram_256__164` | float | 0 |
| `byte_features__byte_entropy_histogram_256__165` | float | 0 |
| `byte_features__byte_entropy_histogram_256__166` | float | 0 |
| `byte_features__byte_entropy_histogram_256__167` | float | 0 |
| `byte_features__byte_entropy_histogram_256__168` | float | 0 |
| `byte_features__byte_entropy_histogram_256__169` | float | 0 |
| `byte_features__byte_entropy_histogram_256__170` | float | 0 |
| `byte_features__byte_entropy_histogram_256__171` | float | 0 |
| `byte_features__byte_entropy_histogram_256__172` | float | 0 |
| `byte_features__byte_entropy_histogram_256__173` | float | 0 |
| `byte_features__byte_entropy_histogram_256__174` | float | 0 |
| `byte_features__byte_entropy_histogram_256__175` | float | 0 |
| `byte_features__byte_entropy_histogram_256__176` | float | 0 |
| `byte_features__byte_entropy_histogram_256__177` | float | 0 |
| `byte_features__byte_entropy_histogram_256__178` | float | 0 |
| `byte_features__byte_entropy_histogram_256__179` | float | 0 |
| `byte_features__byte_entropy_histogram_256__180` | float | 0 |
| `byte_features__byte_entropy_histogram_256__181` | float | 0 |
| `byte_features__byte_entropy_histogram_256__182` | float | 0 |
| `byte_features__byte_entropy_histogram_256__183` | float | 0 |
| `byte_features__byte_entropy_histogram_256__184` | float | 0 |
| `byte_features__byte_entropy_histogram_256__185` | float | 0 |
| `byte_features__byte_entropy_histogram_256__186` | float | 0 |
| `byte_features__byte_entropy_histogram_256__187` | float | 0 |
| `byte_features__byte_entropy_histogram_256__188` | float | 0 |
| `byte_features__byte_entropy_histogram_256__189` | float | 0 |
| `byte_features__byte_entropy_histogram_256__190` | float | 0 |
| `byte_features__byte_entropy_histogram_256__191` | float | 0 |
| `byte_features__byte_entropy_histogram_256__192` | float | 0 |
| `byte_features__byte_entropy_histogram_256__193` | float | 0 |
| `byte_features__byte_entropy_histogram_256__194` | float | 0 |
| `byte_features__byte_entropy_histogram_256__195` | float | 0 |
| `byte_features__byte_entropy_histogram_256__196` | float | 0 |
| `byte_features__byte_entropy_histogram_256__197` | float | 0 |
| `byte_features__byte_entropy_histogram_256__198` | float | 0 |
| `byte_features__byte_entropy_histogram_256__199` | float | 0 |
| `byte_features__byte_entropy_histogram_256__200` | float | 0 |
| `byte_features__byte_entropy_histogram_256__201` | float | 0 |
| `byte_features__byte_entropy_histogram_256__202` | float | 0 |
| `byte_features__byte_entropy_histogram_256__203` | float | 0 |
| `byte_features__byte_entropy_histogram_256__204` | float | 0 |
| `byte_features__byte_entropy_histogram_256__205` | float | 0 |
| `byte_features__byte_entropy_histogram_256__206` | float | 0 |
| `byte_features__byte_entropy_histogram_256__207` | float | 0 |
| `byte_features__byte_entropy_histogram_256__208` | float | 0 |
| `byte_features__byte_entropy_histogram_256__209` | float | 0 |
| `byte_features__byte_entropy_histogram_256__210` | float | 0 |
| `byte_features__byte_entropy_histogram_256__211` | float | 0 |
| `byte_features__byte_entropy_histogram_256__212` | float | 0 |
| `byte_features__byte_entropy_histogram_256__213` | float | 0 |
| `byte_features__byte_entropy_histogram_256__214` | float | 0 |
| `byte_features__byte_entropy_histogram_256__215` | float | 0 |
| `byte_features__byte_entropy_histogram_256__216` | float | 0 |
| `byte_features__byte_entropy_histogram_256__217` | float | 0 |
| `byte_features__byte_entropy_histogram_256__218` | float | 0 |
| `byte_features__byte_entropy_histogram_256__219` | float | 0 |
| `byte_features__byte_entropy_histogram_256__220` | float | 0 |
| `byte_features__byte_entropy_histogram_256__221` | float | 0 |
| `byte_features__byte_entropy_histogram_256__222` | float | 0 |
| `byte_features__byte_entropy_histogram_256__223` | float | 0 |
| `byte_features__byte_entropy_histogram_256__224` | float | 0 |
| `byte_features__byte_entropy_histogram_256__225` | float | 0 |
| `byte_features__byte_entropy_histogram_256__226` | float | 0 |
| `byte_features__byte_entropy_histogram_256__227` | float | 0 |
| `byte_features__byte_entropy_histogram_256__228` | float | 0 |
| `byte_features__byte_entropy_histogram_256__229` | float | 0 |
| `byte_features__byte_entropy_histogram_256__230` | float | 0 |
| `byte_features__byte_entropy_histogram_256__231` | float | 0 |
| `byte_features__byte_entropy_histogram_256__232` | float | 0 |
| `byte_features__byte_entropy_histogram_256__233` | float | 0 |
| `byte_features__byte_entropy_histogram_256__234` | float | 0 |
| `byte_features__byte_entropy_histogram_256__235` | float | 0 |
| `byte_features__byte_entropy_histogram_256__236` | float | 0 |
| `byte_features__byte_entropy_histogram_256__237` | float | 0 |
| `byte_features__byte_entropy_histogram_256__238` | float | 0 |
| `byte_features__byte_entropy_histogram_256__239` | float | 0 |
| `byte_features__byte_entropy_histogram_256__240` | float | 0 |
| `byte_features__byte_entropy_histogram_256__241` | float | 0 |
| `byte_features__byte_entropy_histogram_256__242` | float | 0 |
| `byte_features__byte_entropy_histogram_256__243` | float | 0 |
| `byte_features__byte_entropy_histogram_256__244` | float | 0 |
| `byte_features__byte_entropy_histogram_256__245` | float | 0 |
| `byte_features__byte_entropy_histogram_256__246` | float | 0 |
| `byte_features__byte_entropy_histogram_256__247` | float | 0 |
| `byte_features__byte_entropy_histogram_256__248` | float | 0 |
| `byte_features__byte_entropy_histogram_256__249` | float | 0 |
| `byte_features__byte_entropy_histogram_256__250` | float | 0 |
| `byte_features__byte_entropy_histogram_256__251` | float | 0 |
| `byte_features__byte_entropy_histogram_256__252` | float | 0 |
| `byte_features__byte_entropy_histogram_256__253` | float | 0 |
| `byte_features__byte_entropy_histogram_256__254` | float | 0 |
| `byte_features__byte_entropy_histogram_256__255` | float | 0 |
| `byte_features__byte_entropy_histogram_256__n` | int64 | 0 |
| `strings__count_ascii` | int64 | 0 |
| `strings__count_utf16` | int64 | 0 |
| `strings__count_total` | int64 | 0 |
| `strings__chars_total` | int64 | 0 |
| `strings__printable_ratio` | double | 0 |
| `strings__len_mean` | double | 0 |
| `strings__len_max` | int64 | 0 |
| `strings__urls__n` | int64 | 0 |
| `strings__n_urls` | int64 | 0 |
| `strings__ipv4__n` | int64 | 0 |
| `strings__n_ipv4` | int64 | 0 |
| `strings__ipv4_plausible__n` | int64 | 0 |
| `strings__n_ipv4_plausible` | int64 | 0 |
| `strings__dll_names__longueur` | int32 | 1 579 |
| `strings__dll_names__n` | int64 | 0 |
| `strings__n_dll_names` | int64 | 0 |
| `strings__registry_paths__longueur` | int32 | 81 214 |
| `strings__registry_paths__n` | int64 | 0 |
| `strings__n_registry_paths` | int64 | 0 |
| `strings__file_paths__n` | int64 | 0 |
| `strings__n_file_paths` | int64 | 0 |
| `strings__urls__longueur` | int32 | 62 933 |
| `strings__ipv4__longueur` | int32 | 53 230 |
| `strings__ipv4_plausible__longueur` | int32 | 87 511 |
| `strings__file_paths__longueur` | int32 | 72 894 |
| `overlay__size` | int64 | 0 |
| `overlay__offset` | int64 | 0 |
| `overlay__entropy` | double | 61 772 |
| `overlay__magic_head` | string | 61 772 |
| `overlay__sha256` | string | 61 772 |
| `entrypoint_bytes__offset` | int64 | 2 813 |
| `entrypoint_bytes__hex` | string | 2 813 |
| `entrypoint_bytes__entropy` | double | 2 813 |

## `familles.parquet`

Family name, its source, and the threat labels.

- rows: 100 909
- columns: 23

| Column | Type | Nulls |
|---|---|---|
| `anti_analysis` | bool | 21 077 |
| `comportements` | large_string | 51 064 |
| `source_comportement` | large_string | 40 634 |
| `menace_stealer` | bool | 40 634 |
| `menace_loader` | bool | 40 634 |
| `menace_banker` | bool | 40 634 |
| `menace_rat` | bool | 40 634 |
| `menace_ransomware` | bool | 40 634 |
| `menace_botnet` | bool | 40 634 |
| `menace_worm` | bool | 40 634 |
| `menace_keylogger` | bool | 40 634 |
| `menace_miner` | bool | 40 634 |
| `menace_fileinfector` | bool | 40 634 |
| `menace_backdoor` | bool | 40 634 |
| `menace_postexploitation` | bool | 40 634 |
| `menace_clipper` | bool | 40 634 |
| `menace_downloader` | bool | 40 634 |
| `menace_adware` | bool | 40 634 |

## `decoupages.parquet`

The five frozen splitting policies.

- rows: 100 909
- columns: 30

| Column | Type | Nulls |
|---|---|---|
| `groupe` | large_string | 0 |
| `groupe_famille` | large_string | 0 |
| `split_random` | large_string | 0 |
| `split_group` | large_string | 0 |
| `split_family` | large_string | 0 |
| `anti_analysis` | bool | 21 077 |
| `comportements` | large_string | 51 064 |
| `source_comportement` | large_string | 51 064 |
| `menace_stealer` | bool | 40 634 |
| `menace_loader` | bool | 40 634 |
| `menace_banker` | bool | 40 634 |
| `menace_rat` | bool | 40 634 |
| `menace_ransomware` | bool | 40 634 |
| `menace_botnet` | bool | 40 634 |
| `menace_worm` | bool | 40 634 |
| `menace_keylogger` | bool | 40 634 |
| `menace_miner` | bool | 40 634 |
| `menace_fileinfector` | bool | 40 634 |
| `menace_backdoor` | bool | 40 634 |
| `menace_postexploitation` | bool | 40 634 |
| `menace_clipper` | bool | 40 634 |
| `menace_downloader` | bool | 40 634 |
| `menace_adware` | bool | 40 634 |
| `split_temps` | large_string | 15 784 |
| `split_croise` | large_string | 0 |
