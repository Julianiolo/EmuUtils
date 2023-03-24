#ifndef __EMUUTILS_SYMBOLTABLE_H__
#define __EMUUTILS_SYMBOLTABLE_H__

#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <tuple>

#include "ElfReader.h"

namespace EmuUtils {
	class ATmega32u4;

	class SymbolTable {
	public:
		typedef uint64_t symb_size_t;

		struct Symbol {
			struct Flags {
				uint8_t scope = Flags_Scope_None;
				bool isWeak = false;
				bool isConstuctor = false;
				bool isWarning = false;
				uint8_t indirectFlags = Flags_Indirect_Normal;
				uint8_t debugDynamicFlags = Flags_DebDyn_Normal;
				uint8_t funcFileObjectFlags = Flags_FuncFileObj_Normal;

				bool operator==(const Flags& other) const;
			};
			enum Flags_Scope {
				Flags_Scope_None = 0,
				Flags_Scope_Local = 1<<0,
				Flags_Scope_Global = 1<<1,
				Flags_Scope_Unique = 1<<2
			};
			enum Flags_Indirect {
				Flags_Indirect_Normal = 0,
				Flags_Indirect_RefrenceToSymbol = 1,
				Flags_Indirect_evalWhileReloc = 2
			};
			enum Flags_DebDyn {
				Flags_DebDyn_Normal = 0,
				Flags_DebDyn_DebugSymbol = 1,
				Flags_DebDyn_DynamicSymbol = 2
			};
			enum Flags_FuncFileObj {
				Flags_FuncFileObj_Normal = 0,
				Flags_FuncFileObj_Function = 1,
				Flags_FuncFileObj_File = 2,
				Flags_FuncFileObj_Obj = 3,
				Flags_FuncFileObj_Section = 4,
			};

			struct Section {
				std::string name;
				Section();
				Section(const std::string& name);

				bool operator==(const Section& other) const;
				size_t sizeBytes() const;
			};

			symb_size_t value;
			Flags flags;
			std::string flagStr;
			std::string name;
			std::string demangled;
			std::string note;
			bool hasDemangledName = false;
			symb_size_t size;
			std::string section;

			uint32_t id = -1;

			bool isHidden = false;

			void* extraData = nullptr;

			symb_size_t addrEnd() const;

			void getState(std::ostream& output);
			void setState(std::istream& input);

			bool operator<(const Symbol& rhs) const;
			bool operator==(const Symbol& other) const;	
			bool equals(const Symbol& other, bool includeID = true) const;
			size_t sizeBytes() const;
		};

		typedef std::vector<std::string> (*SymbolsAddDemanglFuncPtr)(std::vector<const char*> names, void* userData);
		typedef std::vector<uint32_t> SymbolList;
	private:
		ATmega32u4* mcu;

		SymbolsAddDemanglFuncPtr symbolsAddDemanglFunc = nullptr;
		void* symbolsAddDemanglFuncUserData = nullptr;

		std::vector<Symbol> symbolStorage;
		std::map<std::string, Symbol::Section> sections;

		std::map<uint32_t, size_t> symbsIdMap;
		std::map<std::string, uint32_t> symbsNameMap;
		std::map<std::string, std::vector<uint32_t>> symbolsBySections;

		std::vector<uint32_t> symbolsRam;
		std::vector<uint32_t> symbolsRom;

		symb_size_t maxRamAddrEnd = 0;

		uint32_t genSymbolId();

		Symbol::Flags generateSymbolFlags(const char* str);
		std::string generateSymbolSection(const char* str, const char* strEnd = 0, size_t* sectStrLen = nullptr);
		Symbol parseLine(const char* start, const char* end);
		size_t parseList(std::vector<Symbol>* vec,const char* str, size_t size = -1);

		void setupConnections(size_t cnt, bool postProc = true); 

		void resetAll();
	public:

		void setSymbolsAddDemanglFunc(SymbolsAddDemanglFuncPtr func, void* userData);

		void addSymbol(Symbol&& symbol); // sets id if id==-1

		void generateFlagStrForSymbol(Symbol* symbol);


		bool hasSymbols() const;

		bool loadFromDump(const char* str, const char* str_end=0);
		bool loadFromDumpFile(const char* path);
		bool loadFromELF(const ELF::ELFFile& elf);
		bool loadDeviceSymbolDump(const char* str, const char* str_end=0);
		bool loadDeviceSymbolDumpFile(const char* path);

		const Symbol::Section* getSection(const std::string& name) const;
		const Symbol* getSymbolByName(const std::string& name) const;
		const Symbol* getSymbolByValue(const symb_size_t value, const SymbolList& list) const;
		const Symbol* getSymbolById(uint32_t id) const;

		const std::vector<Symbol>& getSymbols() const;
		const std::map<std::string, Symbol::Section>& getSections() const;

		const Symbol* getSymbol(const SymbolList& symbs, size_t ind) const;
		const SymbolList& getSymbolsRam() const;
		const SymbolList& getSymbolsRom() const;
		const SymbolList& getSymbolsBySection(const std::string& section) const;

		symb_size_t getMaxRamAddrEnd() const;

		std::vector<std::pair<uint32_t, std::string>> getFuncSymbols() const;
		std::pair<std::vector<std::tuple<std::string, uint32_t, uint32_t>>,std::vector<uint32_t>> getDataSymbolsAndDisasmSeeds() const;

		void getState(std::ostream& output);
		void setState(std::istream& input);

		bool operator==(const SymbolTable& other) const;
		size_t sizeBytes() const;


		class SymbolFeeder {
		private:
			const SymbolTable* table;
			SymbolList list;
			size_t curr = 0;
		public:
			SymbolFeeder(const SymbolTable* table, const SymbolList& list);

			const Symbol* getSymbol(symb_size_t addr);
		};
	};
}

namespace DataUtils {
	inline size_t approxSizeOf(const EmuUtils::SymbolTable::Symbol::Section& v) {
		return v.sizeBytes();
	}
	inline size_t approxSizeOf(const EmuUtils::SymbolTable::Symbol& v) {
		return v.sizeBytes();
	}
	inline size_t approxSizeOf(const EmuUtils::SymbolTable& v) {
		return v.sizeBytes();
	}
}

#endif