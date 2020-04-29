/*
* read_rel.plt.c
*
* Coded by 1ndr4 (indra.kr@gmail.com)
* 
* https://github.com/indra-kr/Linux-Static-Analysis/blob/master/read_rel_plt.c
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <elf.h>

#define SECTION_HEADER	0x01
#define SYM_TAB_ENT	0x02
#define REL_ENT		0x04

#define ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt " (%s(): %dline)\n", ##__VA_ARGS__, __func__, __LINE__)
#define PRINT(fmt, ...) fprintf(stdout, fmt " (%s(): %dline)\n", ##__VA_ARGS__, __func__, __LINE__)

typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Rel Elf_Rel;

struct reloc_link {
	unsigned int addr;
	char *name;
	void *next;
};

struct reloc_link *rel_link = NULL;

int InsertRelLink(unsigned int addr, const char *name)
{
	struct reloc_link *new = NULL, *cur;
	
	if(addr == 0 || name == NULL)
		return -1;
	if((new = malloc(sizeof(struct reloc_link))) == NULL) {
		ERROR("Out of memory: %d", sizeof(struct reloc_link));
		return -1;
	}

	new->addr = addr;
	if((new->name = malloc(strlen(name) + 1)) == NULL) {
		ERROR("Out of memory: %d", strlen(name));
		goto failed;
	}
	memset(new->name, 0x00, strlen(name) + 1);
	memcpy(new->name, name, strlen(name));
	new->next = NULL;
	if(rel_link == NULL) {
		rel_link = new;
	} else {
		cur = rel_link;
		while(cur->next != NULL) {
			cur = cur->next;
		}
		cur->next = new;
	}

	return 0;
failed:
	if(new != NULL) {
		if(new->name != NULL)
			free(new->name);
		free(new);
	}
	return -1;
}

int DeleteRelLink(void)
{
	struct reloc_link *cur, *next;

	if(rel_link == NULL)
		return 0;
	cur = rel_link;
	while(cur != NULL) {
		free(cur->name);
		next = cur->next;
		free(cur);
		cur = next;
	}
	return 0;
}

int PrintRelLink(void)
{
	struct reloc_link *cur;
	int i = 0;

	if(rel_link == NULL) {
		ERROR("Relocation Entry not found");
		return -1;
	}
	cur = rel_link;
	while(cur != NULL) {
		fprintf(stdout, "[%d] 0x%08X = %s\n", i++, cur->addr, cur->name);
		cur = cur->next;
	}
	return 0;
}

void *ElfGetData(int fd, unsigned int len, off_t offset, int flags)
{
	char *ret = NULL;
	off_t o_offset = 0;

	if((ret = malloc(len)) == NULL) {
		ERROR("Out of memory: %d bytes", len);
		goto failed;
	}
	if(offset != 0) {
		o_offset = lseek(fd, 0, SEEK_CUR);
		lseek(fd, offset, SEEK_SET);
	}
	if(read(fd, ret, len) != len) {
		ERROR("File read error");
		goto failed;
	}
	if(o_offset)
		lseek(fd, o_offset, SEEK_SET);
	return ret;

failed:
	ERROR("Section Header read error");
	if(ret != NULL)
		free(ret);
	return NULL;
}

void code_print(FILE *fp, const unsigned char *data, int sz)
{
	int i = 0, j = 0, c = 0, dec = 64;
	char buf[80];
	fprintf(fp, "%08X  ", i);
	for(i = 0; i < sz; i++) {
		if((i%16 == 0) && (i != 0)) {
			fprintf(fp, "\t");
			for(j = (i - 16); j != i; j++) {
				c = *(data + j);
				fprintf(fp, "%c", isprint(c) != 0 ? c : '.');
			}
			fprintf(fp, "\n%08X  ", i);
		}
		fprintf(fp, "%02X ", *(data + i));
	}
	if(i > j) {
		dec = dec - (((i - j) * 3) + 10);
		memset(buf, 0x00, sizeof(buf));
		memset(buf, 0x20, dec);
		fprintf(fp, "%s", buf);
		for(j; j < i; j++) {
			c = *(data + j);
			fprintf(fp, "%c", isprint(c) != 0 ? c : '.');
		}
	}
	fprintf(fp, "\n\n");
	return;
}

int main(int argc, char **argv)
{
	int fd = 0, i, j, idx = 0, rel_plt_entry = 0;
	int dynsym_size, dynstr_size;
	char *main_section = NULL;
	Elf_Ehdr ehdr;
	Elf_Shdr *shdr = NULL, shdr_buf;
	Elf_Sym *symtab = NULL;
	Elf_Rel *rel = NULL;
	void *dynsym = NULL, *dynstr = NULL, *rel_plt = NULL;

	if(argc < 2) {
		ERROR("Usage: %s <file>", argv[0]);
		goto failed;
	}

	fprintf(stdout, "[*] File open: %s\n", argv[1]);
	if((fd = open(argv[1], O_RDONLY)) < 0) {
		ERROR("File open error: %s", argv[1]);
		goto failed;
	}

	fprintf(stdout, "[*] Read the ELF Header\n");
	if((int)read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
		ERROR("ELF Header read error");
		goto failed;
	}

	lseek(fd, ehdr.e_shstrndx * ehdr.e_shentsize + ehdr.e_shoff, SEEK_SET);
	read(fd, &shdr_buf, sizeof(shdr_buf));
	if((main_section = ElfGetData(fd, shdr_buf.sh_size, shdr_buf.sh_offset, 0)) == NULL)
		goto failed;

	lseek(fd, ehdr.e_shoff, SEEK_SET);

	fprintf(stdout, "[*] Analyzing.....\n");
	for(i = 0; i < ehdr.e_shnum; i++) {
		if((shdr = ElfGetData(fd, sizeof(Elf_Shdr), 0, 0)) == NULL)
			goto failed;

		if(shdr->sh_size == 0)
			continue;

		if(strcmp(main_section + shdr->sh_name, ".dynsym") == 0) {
			if((dynsym = ElfGetData(fd, shdr->sh_size, shdr->sh_offset, 0)) == NULL)
				goto failed;

			dynsym_size = shdr->sh_size;
		}
		if(strcmp(main_section + shdr->sh_name, ".dynstr") == 0) {
			if((dynstr = ElfGetData(fd, shdr->sh_size, shdr->sh_offset, 0)) == NULL)
				goto failed;

			dynstr_size = shdr->sh_size;
		}

		if(strcmp(main_section + shdr->sh_name, ".rel.plt") == 0) {
			if((rel_plt = ElfGetData(fd, shdr->sh_size, shdr->sh_offset, 0)) == NULL)
				goto failed;
			rel = rel_plt;
			rel_plt_entry = shdr->sh_size/shdr->sh_entsize;	
		}
		free(shdr); shdr = NULL;

       }

	fprintf(stdout, "[*] .rel.plt's Entry: %d\n", rel_plt_entry);
	j = 0;
	for(i = 0; i <= rel_plt_entry; i++) {
		idx = ELF32_R_SYM(rel->r_info);
		symtab = dynsym + (idx * sizeof(Elf_Sym));
		if(idx == 0 || rel->r_offset == 0)
			goto except;

		InsertRelLink((unsigned int)rel->r_offset, dynstr + symtab->st_name);
except:
		j += sizeof(Elf_Rel);
		rel = rel_plt + j;

	}

	PrintRelLink();
	DeleteRelLink();

failed:
	if(main_section != NULL)
		free(main_section);
	if(shdr != NULL)
		free(shdr);
	if(dynsym != NULL)
		free(dynsym);
	if(dynstr != NULL)
		free(dynstr);
	if(rel_plt != NULL)
		free(rel_plt);
       	if(fd != 0)
		close(fd);

	fprintf(stdout, "[*] Done\n"); 

	return 0;
}
