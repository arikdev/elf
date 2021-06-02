#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <elf.h>

static char *g_section_names;

typedef struct {
	 Elf64_Addr	rel_address;
	 Elf64_Off	f1;
	 Elf64_Off	f2;
} rel_t;

char *get_section_type(Elf64_Shdr *sec_hdr)
{
	static char section_type[128];

	/*

#define SHT_HASH	5
#define SHT_NOBITS	8
#define SHT_REL		9
#define SHT_LOPROC	0x70000000
#define SHT_HIPROC	0x7fffffff
#define SHT_LOUSER	0x80000000
#define SHT_HIUSER	0xffffffff
	 
	 * */

	switch (sec_hdr->sh_type) {
		case SHT_PROGBITS:
			strncpy(section_type, "PROGBITS", sizeof(section_type));
			break;
		case SHT_SYMTAB:
			strncpy(section_type, "SYMTAB", sizeof(section_type));
			break;
		case SHT_STRTAB:
			strncpy(section_type, "STRTAB", sizeof(section_type));
			break;
		case SHT_RELA:
			strncpy(section_type, "RELA", sizeof(section_type));
			break;
		case SHT_NOTE:
			strncpy(section_type, "NOTE", sizeof(section_type));
			break;
		case SHT_SHLIB:
			strncpy(section_type, "SHLIB", sizeof(section_type));
			break;
		case SHT_NOBITS:
			strncpy(section_type, "NOBITS", sizeof(section_type));
			break;
		case SHT_DYNAMIC:
			strncpy(section_type, "DYNAMIC", sizeof(section_type));
			break;
		case SHT_DYNSYM:
			strncpy(section_type, "DYNSYM", sizeof(section_type));
			break;
		case SHT_NUM:
			strncpy(section_type, "NUM", sizeof(section_type));
			break;
		default:
			snprintf(section_type, sizeof(section_type), "Unkown:%x", sec_hdr->sh_type);
			break;
	}

	return section_type;
}

static void load_secaion_names_section(Elf64_Shdr section_hdrs[], int n, FILE *elf_file)
{
	int i, name_string_table = -1;

	for (i = 0; i < n; i++) {
		if (section_hdrs[i].sh_type == SHT_STRTAB)
			name_string_table = i;
	}

	if (name_string_table == -1)
		return;

	if (!(g_section_names = malloc(section_hdrs[name_string_table].sh_size))) {
		printf("ERROR: failed allocte memeory \n");
		exit(-1);
	}

	if (fseek(elf_file, section_hdrs[name_string_table].sh_offset,  SEEK_SET))  {
		printf("fseek of elf file failed offset:%d \n", section_hdrs[name_string_table].sh_offset);
		free(g_section_names);
		g_section_names = NULL;
		return;
	}
	if (fread(g_section_names, 1, section_hdrs[name_string_table].sh_size, elf_file) < sizeof(Elf64_Shdr)) {
		printf("Failed reading sectaion header \n");
		free(g_section_names);
		g_section_names = NULL;
		return;
	}
}

/*
 

#define SHF_WRITE            (1 << 0)   /* Writable */
#define SHF_ALLOC            (1 << 1)   /* Occupies memory during execution */
#define SHF_EXECINSTR        (1 << 2)   /* Executable */
#define SHF_MERGE            (1 << 4)   /* Might be merged */
#define SHF_STRINGS          (1 << 5)   /* Contains nul-terminated strings */
#define SHF_INFO_LINK        (1 << 6)   /* `sh_info' contains SHT index */
#define SHF_LINK_ORDER       (1 << 7)   /* Preserve order after combining */
#define SHF_OS_NONCONFORMING (1 << 8)   /* Non-standard OS specific handling
                                           required */
#define SHF_GROUP            (1 << 9)   /* Section is member of a group.  */
#define SHF_TLS              (1 << 10)  /* Section hold thread-local data.  */
#define SHF_COMPRESSED       (1 << 11)  /* Section with compressed data. */
#define SHF_MASKOS           0x0ff00000 /* OS-specific.  */
#define SHF_MASKPROC         0xf0000000 /* Processor-specific */
#define SHF_ORDERED          (1 << 30)  /* Special ordering requirement
                                           (Solaris).  */
#define SHF_EXCLUDE          (1U << 31) /* Section is excluded unless


   */

static void handle_show_sections(Elf64_Shdr section_hdrs[], int n)
{
	int i;
	char flags[64];

	printf("name,type,size\n");
	for (i = 0; i < n; i++) {
		flags[0] = 0;
		if (section_hdrs[i].sh_flags & SHF_WRITE)
			strcat(flags, "w");
		if (section_hdrs[i].sh_flags & SHF_EXECINSTR)
			strcat(flags, "x");
		if (section_hdrs[i].sh_flags & SHF_ALLOC)
			strcat(flags, "a");
		printf("%d\n", i);
		printf("%s,%s,%d,%s,%d\n", g_section_names + section_hdrs[i].sh_name, get_section_type(section_hdrs + i), section_hdrs[i].sh_size, flags,
				section_hdrs[i].sh_offset);
		/*
		printf("  >>> Falgs :%x \n", section_hdrs[i].sh_flags);
		printf("  >>> Info :%x \n", section_hdrs[i].sh_info);
		printf("  >>> Link :%x \n", section_hdrs[i].sh_link);
		*/
	}
}

static void handle_rela_sections(Elf64_Shdr section_hdrs[], int num_of_sections, FILE *elf_file)
{
	int i, j,  n;
	char *data = NULL;
	rel_t rel;

	for (i = 0; i < num_of_sections; i++) {
		if (section_hdrs[i].sh_type != SHT_RELA)
			continue;
		printf("RELA %s\n", g_section_names + section_hdrs[i].sh_name);

		if (!(data = malloc(section_hdrs[i].sh_size))) {
			printf("ERROR: malloc failed \n");
			return;
		}

		if (fseek(elf_file, section_hdrs[i].sh_offset, SEEK_SET)) {
			printf("fseek of elf file failed offset:%d \n", section_hdrs[i].sh_offset);
			free(data);
			return;
		}
		if (fread(data, 1, section_hdrs[i].sh_size, elf_file) < section_hdrs[i].sh_size) {
			printf("Failed reading sectaion header \n");
			free(data);
			return;
		}

		n = section_hdrs[i].sh_size / 24;
		for (j = 0; j < n; j++) {
			memcpy(&rel, data + j * 24, 24);
			printf("Addres:%llx Info:%llx Type:%llx\n", rel.rel_address, rel.f1, rel.f2);
		}
#if 0
#endif
	}
}

void main(int argc, char **argv)
{
	char *file_name = NULL;
	int opt, n, i;
	FILE *elf_file;
	Elf64_Ehdr elf_hdr;
	Elf64_Shdr *section_hdrs;
	bool show_sections = false, show_header = false;
	char *section_type = NULL;

	while ((opt = getopt(argc, argv, "f:sht:")) != -1) {
		switch (opt) {
			case 'f':
				file_name = optarg;
				break;
			case 'h':
				show_header = true;
				break;
			case 's':
				show_sections = true;
				break;
			case 't':
				section_type = optarg;
				break;
			default:
				printf("Invalid argument %c ignored\n", opt);
				break;
		}
	}

	if (!file_name) {
		printf("usage: %s -f filename [-s show sections]\n", argv[0]);
		return;
	}

	if (!(elf_file = fopen(file_name, "r"))) {
		printf("Failed opnening file %s\n", file_name);
		return;
	}

	if ((n = fread((char *)&elf_hdr, 1, sizeof(Elf64_Ehdr), elf_file)) < sizeof(Elf64_Ehdr)) {
		printf("Failed to read elf header\n");
		return;
	}

	if (show_header) {
		printf("Type :%x \n", elf_hdr.e_type);
		printf("Machine :%x \n", elf_hdr.e_machine);
		printf("Section headers offset :%d \n", elf_hdr.e_shoff);
		printf("Section headers size :%d \n", elf_hdr.e_shentsize);
		printf("Section headers number :%d \n", elf_hdr.e_shnum);
	}

	if (!(section_hdrs = malloc(elf_hdr.e_shnum * sizeof(Elf64_Shdr)))) {
		printf("ERROR : failed memory allocation \n");
		return;
	}

	if (fseek(elf_file, elf_hdr.e_shoff, SEEK_SET))  {
		printf("fseek of elf file failed offset:%d \n", elf_hdr.e_shoff);
		return;
	}

	for (i = 0; i < elf_hdr.e_shnum; i++) {
		if (fread(section_hdrs + i, 1, sizeof(Elf64_Shdr), elf_file) < sizeof(Elf64_Shdr)) {
			printf("Failed reading sectaion header #%d \n", i);
			free(section_hdrs);
			return;
		}
	}

	load_secaion_names_section(section_hdrs, elf_hdr.e_shnum, elf_file);

	if (show_sections)
		handle_show_sections(section_hdrs, elf_hdr.e_shnum);

	if (section_type) {
		if (!strcmp(section_type, "RELA"))
			handle_rela_sections(section_hdrs, elf_hdr.e_shnum, elf_file);
	}
}
