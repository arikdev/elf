#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

static char *g_section_names;

char *get_section_type(Elf64_Shdr *sec_hdr)
{
	static char section_type[128];

	/*

#define SHT_HASH	5
#define SHT_DYNAMIC	6
#define SHT_NOTE	7
#define SHT_NOBITS	8
#define SHT_REL		9
#define SHT_SHLIB	10
#define SHT_DYNSYM	11
#define SHT_NUM		12
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
		default:
			strncpy(section_type, "Unkown", sizeof(section_type));
			break;
	}
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

	printf("Offset: %x\n", section_hdrs[name_string_table].sh_offset);

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

void main(int argc, char **argv)
{
	char *file_name = NULL;
	int opt, n, i;
	FILE *elf_file;
	Elf64_Ehdr elf_hdr;
	Elf64_Shdr *section_hdrs;

	while ((opt = getopt(argc, argv, "f:")) != -1) {
		switch (opt) {
			case 'f':
				file_name = optarg;
				break;
			default:
				printf("Invalid argument %c ignored\n", opt);
				break;
		}
	}

	if (!file_name) {
		printf("usage: %s -f filename\n", argv[0]);
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

	printf("Type :%x \n", elf_hdr.e_type);
	printf("Machine :%x \n", elf_hdr.e_machine);
	printf("Section headers offset :%d \n", elf_hdr.e_shoff);
	printf("Section headers size :%d \n", elf_hdr.e_shentsize);
	printf("Section headers number :%d \n", elf_hdr.e_shnum);

	if (!(section_hdrs =  malloc(elf_hdr.e_shnum * sizeof(Elf64_Shdr)))) {
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

	printf("The sections \n");
	for (i = 0; i < elf_hdr.e_shnum; i++) {
		printf(">>>> Section #%d \n", i);
		printf("  >> %s \n", get_section_type(section_hdrs + i));
		printf("  >>> Name :%s \n", g_section_names + section_hdrs[i].sh_name);
		printf("  >>> Falgs :%x \n", section_hdrs[i].sh_flags);
		printf("  >>> Info :%x \n", section_hdrs[i].sh_info);
		printf("  >>> Link :%x \n", section_hdrs[i].sh_link);
		printf("  >>> Size :%d \n", section_hdrs[i].sh_size);
	}
}
