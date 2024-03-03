#include "stdafx.h"
#include <unistd_uw.h>
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include <getopt.h>

class CPe64Module
{
protected:
	union {
		HMODULE m_mod;
		PIMAGE_DOS_HEADER m_dosh;
	};
	uint8_t* rdata_s = 0, * rdata_e = 0;
	uint8_t* text_s = 0, * text_e = 0;
	uint8_t* m_entryfunc = 0;
	intptr_t m_obase = 0;

public:
	CPe64Module(HMODULE mod, const char * dllname) : m_mod(mod) {
		HANDLE hf = CreateFileA(dllname, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hf != INVALID_HANDLE_VALUE) {
			char buf[0x1000];
			DWORD rd;
			if (ReadFile(hf, buf, sizeof(buf), &rd, NULL)) {
				PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buf;
				PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)(buf + dos->e_lfanew);
				m_obase = nth->OptionalHeader.ImageBase;
			}
			CloseHandle(hf);
		}
		
		uint8_t* mod0 = (uint8_t*)mod;
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
		PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)(mod0 + dos->e_lfanew);

		auto const secs = (IMAGE_SECTION_HEADER*)(nth + 1);
		std::map<uint8_t*, IMAGE_SECTION_HEADER*> secmap;
		for (int i = 0; i < nth->FileHeader.NumberOfSections; ++i)
		{
			secmap[secs[i].VirtualAddress + mod0] = secs + i;
			if (strcmp((char*)secs[i].Name, ".rdata") == 0)
			{
				rdata_s = mod0 + secs[i].VirtualAddress;
				rdata_e = rdata_s + secs[i].Misc.VirtualSize;
			}
			if (strcmp((char*)secs[i].Name, ".text") == 0)
			{
				text_s = mod0 + secs[i].VirtualAddress;
				text_e = text_s + secs[i].Misc.VirtualSize;
			}
		}
		m_entryfunc = 0;
		if (nth->OptionalHeader.AddressOfEntryPoint)
			m_entryfunc = mod0 + nth->OptionalHeader.AddressOfEntryPoint;
	}

	template <class CB>
	void iter_runtime_funcs(const CB & cb)
	{
		uint8_t* mod0 = (uint8_t*)m_mod;
		PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)(mod0 + m_dosh->e_lfanew);
		auto& dr = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		RUNTIME_FUNCTION* fs = (RUNTIME_FUNCTION*)(mod0 + dr.VirtualAddress);
		for (uint32_t i = 0u, mi = dr.Size / sizeof(RUNTIME_FUNCTION); i < mi; ++i)
		{
			cb(mod0 + fs[i].BeginAddress, mod0 + fs[i].EndAddress, m_obase + fs[i].BeginAddress);
		}
	}
};

class SimpStat
{
	std::map<uint8_t*, int> m_stat;
	std::vector<int> m_counts;
public:
	void add(uint8_t* xx) {
		auto it = m_stat.find(xx);
		if (it == m_stat.end()) {
			m_stat[xx] = (int) m_counts.size();
			m_counts.push_back(1);
		} else {
			m_counts[it->second]++;
		}
	}
	string indentity() {
		string ss;
		for (auto cnt : m_counts) {
			ss += std::to_string(cnt) + ",";
		}
		if (!ss.empty()) ss.pop_back();
		return ss;
	}
	string sorted_iden() {
		vector<int> cp(m_counts);
		std::sort(cp.begin(), cp.end(), std::greater<int>());
		string ss;
		for (auto cnt : cp) {
			ss += std::to_string(cnt) + ",";
		}
		if (!ss.empty()) ss.pop_back();
		return ss;
	}
};

string get_rsa_pub(RSA* rsa) {
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(bio, rsa);
	char* p = 0;
	int len = BIO_get_mem_data(bio, &p);
	string s(p, len);
	BIO_free(bio);
	return s;
}

int print_ctp_version(const char * dllname)
{
	HMODULE mod = LoadLibraryA(dllname);
	if (!mod)
	{
		printf("LoadLibraryA failed\n");
		return -1;
	}
	const char* (*get_version)(void);
	*(void**)&get_version = GetProcAddress(mod, "?GetApiVersion@CThostFtdcTraderApi@@SAPEBDXZ");
	string version("unknown version");
	if (get_version) {
		version = get_version();
	}

	vector<uint8_t*> vfuncs;
	CPe64Module pe(mod, dllname);
	pe.iter_runtime_funcs([&](uint8_t* s, uint8_t* e, intptr_t orgf) {
		SimpStat st;
		const int sz = (int)(e - s);
		const auto s0 = s;
		for (; s < e;) {
			int len = get_instruction_length_amd64(s);
			if (len < 1) len = 1;
			if (len == 5 && s[0] == 0xe8) {
				int32_t rel = *(int32_t*)(s + 1);
				uint8_t* target = s + 5 + rel;
				st.add(target);
			}
			s += len;
		}
		
		string iden = st.indentity();
		// printf("runtime func: %#zx[%x] iden=%s\n", orgf, sz, iden.c_str());
		if (iden == "1,7,8,1,1,1,1")
		{
			vfuncs.push_back(s0);
		}
	});
	int rv;
	if (vfuncs.empty()) {
		fprintf(stderr, "function not found!\n");
		rv = -1;
	}
	else if (vfuncs.size() > 1) {
		fprintf(stderr, "got %d funcs, there should be only one!\n", (int)vfuncs.size());
		rv = -1;
	}
	else {
		uint8_t* func = vfuncs[0];
		fprintf(stderr, "[INFO] found function: %#zx\n", func - (uint8_t*)mod);
		int (*get_key)(RSA** rsa, const char * ver);
		*(void**)&get_key = func;
		RSA* rsa = 0;
		get_key(&rsa, "API_20171207_V1");
		if (rsa) {
			string s = get_rsa_pub(rsa);
			printf("=====%s=====\n%s\n", version.c_str(), s.c_str());
			// RSA_free(rsa); // we cant free, it's alloced by the dll.
			rv = 0;
		}
		else {
			fprintf(stderr, "failed to get rsa\n");
			rv = -1;
		}
	}

	FreeLibrary(mod);
	return rv;
}

void test_dep()
{
	RSA* rsa = RSA_new();
	RSA_public_decrypt(0, NULL, NULL, rsa, RSA_PKCS1_PADDING);
	RSA_free(rsa);
}

static int usage() {
	fprintf(stderr, "ctp public key finder for windows.\nusage: ctpver file.dll [file2.dll ...]\n");
	return 1;
}

int main(int argc, char ** argv)
{
	uw_enable_utf8(&test_dep);
	for (;;)
	{
		int ch = getopt(argc, argv, "v");
		if (ch < 0) break;
		if (ch == 'v') (void)0;
		else return usage();
	}
	argc -= optind;
	argv += optind;
	if (argc == 0) return usage();
	for (int i = 0; i < argc; ++i) {
		print_ctp_version(argv[i]);
	}
	return 0;
}
