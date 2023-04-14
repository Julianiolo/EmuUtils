#include "SymbolTable.h"

#include <algorithm>
#include <cstring>
#include <cmath>

#include "StringUtils.h"
#include "StreamUtils.h"
#include "DataUtils.h"
#include "LogUtils.h"
#include "DataUtilsSize.h"


#define LU_MODULE "SymbolTable"

bool EmuUtils::SymbolTable::Symbol::Flags::operator==(const Flags& other) const{
#define _CMP_(x) (x==other.x)
	return _CMP_(scope) && 
		_CMP_(isWeak) && _CMP_(isConstuctor) && _CMP_(isWarning) && 
		_CMP_(indirectFlags) && _CMP_(debugDynamicFlags) && _CMP_(funcFileObjectFlags);
#undef _CMP_
}




EmuUtils::SymbolTable::Symbol::Section::Section() {

}
EmuUtils::SymbolTable::Symbol::Section::Section(const std::string& name) : name(name) {

}
bool EmuUtils::SymbolTable::Symbol::Section::operator==(const Section& other) const{
	return name == other.name;
}



bool EmuUtils::SymbolTable::Symbol::operator<(const Symbol& rhs) const {
	if(value != rhs.value) {
		return value < rhs.value;
	}
	if(name != rhs.name) {
		return name < rhs.name;
	}
	if(size != rhs.size) {
		return size < rhs.size;
	}
	if(section != rhs.section) {
		return section < rhs.section;
	}
	return id < rhs.id;
}
bool EmuUtils::SymbolTable::Symbol::operator==(const Symbol& other) const{
	return equals(other);
}
bool EmuUtils::SymbolTable::Symbol::equals(const Symbol& other, bool includeID) const{
#define _CMP_(x) (x==other.x)
	bool same = _CMP_(value) && _CMP_(flags) && _CMP_(flagStr) && 
		_CMP_(name) && _CMP_(demangled) && _CMP_(note) && 
		_CMP_(hasDemangledName) && _CMP_(size) && _CMP_(section) && _CMP_(isHidden);
	return same && (!includeID || _CMP_(id));
#undef _CMP_
}

uint64_t EmuUtils::SymbolTable::Symbol::addrEnd() const {
	return value + size;
}

void EmuUtils::SymbolTable::setSymbolsAddDemanglFunc(SymbolsAddDemanglFuncPtr func, void* userData){
	symbolsAddDemanglFunc = func;
	symbolsAddDemanglFuncUserData = userData;
}

void EmuUtils::SymbolTable::addSymbol(Symbol&& symbol){
	if(symbol.id == (decltype(symbol.id))-1)
		symbol.id = genSymbolId();

	symbsIdMap[symbol.id] = symbolStorage.size();

	symbolStorage.push_back(symbol);

	setupConnections(1);
}

uint32_t EmuUtils::SymbolTable::genSymbolId(){
	static uint32_t cnt = 0;
	return cnt++;
}

EmuUtils::SymbolTable::Symbol::Flags EmuUtils::SymbolTable::generateSymbolFlags(const char* str) {
	Symbol::Flags flags;
	switch (str[0]) {
		case ' ':
			flags.scope = Symbol::Flags_Scope_None; 
			break;
		case 'l':
			flags.scope = Symbol::Flags_Scope_Local; 
			break;
		case 'g':
			flags.scope = Symbol::Flags_Scope_Global; 
			break;
		case 'u':
			flags.scope = Symbol::Flags_Scope_Global | Symbol::Flags_Scope_Unique; 
			break;
		case '!':
			flags.scope = Symbol::Flags_Scope_Global | Symbol::Flags_Scope_Local; 
			break;
		default:
			abort();
	}

	switch (str[1]) {
		case ' ':
			flags.isWeak = false;
			break;
		case 'w':
			flags.isWeak = true;
			break;
		default:
			abort();
	}

	switch (str[2]) {
		case ' ':
			flags.isConstuctor = false;
			break;
		case 'C':
			flags.isConstuctor = true;
			break;
		default:
			abort();
	}

	switch (str[3]) {
		case ' ':
			flags.isWarning = false;
			break;
		case 'W':
			flags.isWarning = true;
			break;
		default:
			abort();
	}

	switch (str[4]) {
		case ' ':
			flags.indirectFlags = Symbol::Flags_Indirect_Normal;
			break;
		case 'I':
			flags.indirectFlags = Symbol::Flags_Indirect_RefrenceToSymbol;
			break;
		case 'i':
			flags.indirectFlags = Symbol::Flags_Indirect_evalWhileReloc;
			break;
		default:
			abort();
	}

	switch (str[5]) {
		case ' ':
			flags.debugDynamicFlags = Symbol::Flags_DebDyn_Normal;
			break;
		case 'd':
			flags.debugDynamicFlags = Symbol::Flags_DebDyn_DebugSymbol;
			break;
		case 'D':
			flags.debugDynamicFlags = Symbol::Flags_DebDyn_DynamicSymbol;
			break;
		default:
			abort();
	}

	switch (str[6]) {
		case ' ':
			flags.funcFileObjectFlags = Symbol::Flags_FuncFileObj_Normal;
			break;
		case 'F':
			flags.funcFileObjectFlags = Symbol::Flags_FuncFileObj_Function;
			break;
		case 'f':
			flags.funcFileObjectFlags = Symbol::Flags_FuncFileObj_File;
			break;
		case 'O':
			flags.funcFileObjectFlags = Symbol::Flags_FuncFileObj_Obj;
			break;
		default:
			abort();
	}

	return flags;
}
std::string EmuUtils::SymbolTable::generateSymbolSection(const char* str, const char* strEnd, size_t* sectStrLen) {
	if (!strEnd)
		strEnd = str + std::strlen(str);

	while(str<strEnd && *str==' ')
		str++;

	const char* strPtr = str;
	while (*strPtr != '\t' && strPtr != strEnd)
		strPtr++;
	if (sectStrLen)
		*sectStrLen = strPtr - str;

	std::string sectStr = std::string(str, strPtr);
	if (sections.find(sectStr) == sections.end()) {
		sections[sectStr] = Symbol::Section(sectStr);
	}

	return sectStr;
}

EmuUtils::SymbolTable::Symbol EmuUtils::SymbolTable::parseLine(const char* start, const char* end) {
	Symbol symbol;
	size_t ptr = 0;
	symbol.value = StringUtils::hexStrToUIntLen<uint64_t>(start, 8) & 0xFFFF;
	ptr += 8 + 1;

	symbol.flags = generateSymbolFlags(start + ptr);
	symbol.flagStr = std::string(start + ptr, 7);
	ptr += 7 + 1;

	size_t sectStrLen;
	symbol.section = generateSymbolSection(start + ptr, end, &sectStrLen);
	ptr += sectStrLen + 1;

	symbol.size = StringUtils::hexStrToUIntLen<uint64_t>(start + ptr, 8);
	ptr += 8 + 1;

	symbol.isHidden = false;
	if (*(start + ptr) == '.') {
		constexpr char hiddenStr[] = ".hidden";
		if ((start + ptr + sizeof(hiddenStr) <= end) && (std::string(start + ptr, start + ptr + sizeof(hiddenStr) - 1) == hiddenStr)) {
			symbol.isHidden = true;
			ptr += sizeof(hiddenStr) - 1 + 1;
		}
	}

	const char* const tabPos = StringUtils::findCharInStr('\t', start + ptr, end);
	if (tabPos == nullptr) {
		symbol.name = std::string(start + ptr, end);
		symbol.note = "";
	}
	else {
		symbol.name = std::string(start + ptr, tabPos);
		symbol.note = std::string(tabPos + 1, end);
		size_t nlPos;
		while ((nlPos = symbol.note.find("\\n")) != std::string::npos)
			symbol.note.replace(nlPos, 2, "\n");
	}
	symbol.hasDemangledName = false;

	return symbol;
}

size_t EmuUtils::SymbolTable::parseList(std::vector<Symbol>* vec, const char* str, size_t size) {
	constexpr char startStr[] = "SYMBOL TABLE:";
	const char* startStrOff = std::strstr(str, startStr);

	const size_t strOff = startStrOff != nullptr ? (startStrOff-str) + sizeof(startStr) : 0;

	if (size == (size_t)-1)
		size = std::strlen(str);

	size_t cnt = 0;

	size_t lastLineStart = strOff;
	for (size_t i = strOff; i < size; i++) {
		if (str[i] == '\n') {
			size_t off = i;
			while(off > lastLineStart && (str[off-1] == '\r' || str[off-1] == '\n'))
				off--;
			if ((str + off) - (str + lastLineStart) >= (8 + 1 + 7 + 1 + 0 + 1 + 8 + 1)){
				vec->push_back(parseLine(str + lastLineStart, str + off));
				cnt++;
			}
			lastLineStart = i + 1;
		}
	}
	return cnt;
}

void EmuUtils::SymbolTable::setupConnections(size_t cnt, bool postProc) {
	if (postProc && symbolsAddDemanglFunc && symbolStorage.size() > 0) {
		std::vector<const char*> names;
		for (size_t i = (symbolStorage.size()-cnt); i < symbolStorage.size(); i++) {
			names.push_back(symbolStorage[i].name.c_str());
		}
		std::vector<std::string> demangeled = symbolsAddDemanglFunc(names, symbolsAddDemanglFuncUserData);
		for (size_t i = 0; i < cnt; i++) {
			auto& symbol = symbolStorage[(symbolStorage.size() - cnt) + i];
			symbol.hasDemangledName = symbol.name != demangeled[i];
			symbol.demangled = std::move(demangeled[i]);
		}
	}

	std::sort(symbolStorage.begin(), symbolStorage.end());

	allSymbols.clear();
	symbolsRam.clear();
	symbolsRom.clear();
	symbsIdMap.clear();
	symbsNameMap.clear();
	symbolsBySections.clear();

	for (size_t i = 0; i<symbolStorage.size(); ) {
		auto& s = symbolStorage[i];

		uint32_t id;
		if(s.id == (decltype(s.id))-1){
			id = genSymbolId();
			DU_ASSERT(symbsIdMap.find(id) == symbsIdMap.end());
			s.id = id;
		}else{
			id = s.id;
		}

		// check that there are no duplicate symbolnames (exept "")
		if(s.name.size() != 0 && symbsNameMap.find(s.name) != symbsNameMap.end()) {
			if(!s.equals(symbolStorage[symbsIdMap[symbsNameMap[s.name]]],false)) {
				LU_LOGF_(LogUtils::LogLevel_Warning, "Duplicate Symbol name! %s", s.name.c_str());
			}else{
				symbolStorage.erase(symbolStorage.begin() + i);
				continue;
			}
		}
		symbsIdMap[id] = i;
		symbsNameMap[s.name] = id;

		symbolsBySections[s.section].push_back(id);

		if (s.section == ".bss" || s.section == ".data")
			symbolsRam.push_back(id);

		if (s.section == ".text")
			symbolsRom.push_back(id);

		allSymbols.push_back(id);

		i++;
	}

	DU_ASSERT(symbsIdMap.size() == symbolStorage.size());

	maxRamAddrEnd = 0;
	for(auto& sId : symbolsRam){
		auto addrEnd = getSymbolById(sId)->addrEnd();
		if(addrEnd > maxRamAddrEnd)
			maxRamAddrEnd = addrEnd;
	}
}


void EmuUtils::SymbolTable::generateFlagStrForSymbol(Symbol* symbol) {
	symbol->flagStr = "       ";

	// the static asserts are there to make sure the arrays (scopeStrs,...) are correct/up to date

	{
		DU_STATIC_ASSERT(Symbol::Flags_Scope_None == 0);
		DU_STATIC_ASSERT(Symbol::Flags_Scope_Local == 1);
		DU_STATIC_ASSERT(Symbol::Flags_Scope_Global == 2);
		DU_STATIC_ASSERT((Symbol::Flags_Scope_Global | Symbol::Flags_Scope_Local) == 3);
		DU_STATIC_ASSERT((Symbol::Flags_Scope_Global | Symbol::Flags_Scope_Unique) == 6);
	}
	constexpr const char scopeStrs[] = {' ','l','g','!','?','?','u'};
	symbol->flagStr[0] = symbol->flags.scope <= 6 ? scopeStrs[symbol->flags.scope] : '?';

	symbol->flagStr[1] = symbol->flags.isWeak ? 'w' : ' ';

	symbol->flagStr[2] = symbol->flags.isConstuctor ? 'C' : ' ';

	symbol->flagStr[3] = symbol->flags.isWarning ? 'W' : ' ';

	{
		DU_STATIC_ASSERT(Symbol::Flags_Indirect_Normal == 0);
		DU_STATIC_ASSERT(Symbol::Flags_Indirect_RefrenceToSymbol == 1);
		DU_STATIC_ASSERT(Symbol::Flags_Indirect_evalWhileReloc == 2);
	}
	constexpr const char indirectStrs[] = {' ','I','i'};
	symbol->flagStr[4] = symbol->flags.indirectFlags <= 2 ? indirectStrs[symbol->flags.indirectFlags] : '?';

	{
		DU_STATIC_ASSERT(Symbol::Flags_DebDyn_Normal == 0);
		DU_STATIC_ASSERT(Symbol::Flags_DebDyn_DebugSymbol == 1);
		DU_STATIC_ASSERT(Symbol::Flags_DebDyn_DynamicSymbol == 2);
	}
	constexpr const char debugStrs[] = {' ','d','D'};
	symbol->flagStr[5] = symbol->flags.debugDynamicFlags <= 2 ? debugStrs[symbol->flags.debugDynamicFlags] : '?';

	// TODO: there should be a 4th letter for section, but I cant find any resources about what it is
	{
		DU_STATIC_ASSERT(Symbol::Flags_FuncFileObj_Normal == 0);
		DU_STATIC_ASSERT(Symbol::Flags_FuncFileObj_Function == 1);
		DU_STATIC_ASSERT(Symbol::Flags_FuncFileObj_File == 2);
		DU_STATIC_ASSERT(Symbol::Flags_FuncFileObj_Obj == 3);
	}
	constexpr const char ffoStrs[] = {' ','F','f','O'};
	symbol->flagStr[6] = symbol->flags.funcFileObjectFlags <= 3 ? ffoStrs[symbol->flags.funcFileObjectFlags] : '?';
}


bool EmuUtils::SymbolTable::loadFromDump(const char* str, const char* str_end) {
	//resetAll();
	if(!str_end)
		str_end = str + std::strlen(str);

	size_t cnt = parseList(&symbolStorage,str,str_end-str);

	setupConnections(cnt);

	return true;
}
bool EmuUtils::SymbolTable::loadFromDumpFile(const char* path) {
	std::string fileStr;
	try {
		fileStr = StringUtils::loadFileIntoString(path);
	}
	catch (const std::runtime_error& e) {
		LU_LOGF_(LogUtils::LogLevel_Error, "Cannot Open symbol table dump File: \"%s\"", e.what());
		return false;
	}

	return loadFromDump(fileStr.c_str(), fileStr.c_str() + fileStr.size());
}

bool EmuUtils::SymbolTable::loadFromELF(const ELF::ELFFile& elf) {
	//resetAll();
	size_t cnt = 0;
	for (size_t i = 0; i < elf.symbolTableEntrys.size(); i++) {
		auto& symb = elf.symbolTableEntrys[i];
		Symbol symbol;
		symbol.name = elf.stringTableStr + symb.name;
		symbol.value = symb.value & 0xffff; // theres a 8 in the high bits that we need to mask out, idk why its there
		symbol.size = symb.size;
		if (symb.shndx != ELF::ELFFile::SymbolTableEntry::SpecialSectionInd_SHN_UNDEF && symb.shndx < ELF::ELFFile::SymbolTableEntry::SpecialSectionInd_SHN_LORESERVE) {
			symbol.section = generateSymbolSection(elf.shstringTableStr + elf.sectionHeaders[symb.shndx].name);
		}
		else {
			const char* str = "";
			switch (symb.shndx) {
				case ELF::ELFFile::SymbolTableEntry::SpecialSectionInd_SHN_UNDEF:
					str = "UNDEF";
					break;
				case ELF::ELFFile::SymbolTableEntry::SpecialSectionInd_SHN_ABS:
					str = "ABS";
					break;
				case ELF::ELFFile::SymbolTableEntry::SpecialSectionInd_SHN_COMMON:
					str = "COMMON";
					break;
			}
			symbol.section = generateSymbolSection(str);
		}


		{
			auto bind = symb.getInfoBinding();
			//                                       LOCAL                      GLOBAL                      WEAK
			constexpr uint8_t infoToBindFlagLUT[] = {Symbol::Flags_Scope_Local, Symbol::Flags_Scope_Global, Symbol::Flags_Scope_Global};
			symbol.flags.scope = bind <= 2 ? infoToBindFlagLUT[bind] : (uint8_t)Symbol::Flags_Scope_None;

			symbol.flags.isWeak = bind == ELF::ELFFile::SymbolTableEntry::SymbolInfoBinding_Weak;
		}
		{
			auto type = symb.getInfoType();
			constexpr uint8_t infoToTypeFlagLUT[] = {Symbol::Flags_FuncFileObj_Normal, Symbol::Flags_FuncFileObj_Obj, Symbol::Flags_FuncFileObj_Function, Symbol::Flags_FuncFileObj_File, Symbol::Flags_FuncFileObj_Section};
			symbol.flags.funcFileObjectFlags = type <= 4 ? infoToTypeFlagLUT[type] : (uint8_t)Symbol::Flags_FuncFileObj_Normal;
		}

		symbol.flags.debugDynamicFlags = Symbol::Flags_DebDyn_Normal;
		symbol.flags.indirectFlags = Symbol::Flags_Indirect_Normal;

		symbol.flags.isConstuctor = false;
		symbol.flags.isWarning = false;

		symbol.isHidden = false; // idk how to read that???
		generateFlagStrForSymbol(&symbol);

		symbol.hasDemangledName = false;

		symbolStorage.push_back(symbol);
		cnt++;
	}

	setupConnections(cnt);
	return true;
}

bool EmuUtils::SymbolTable::loadDeviceSymbolDump(const char* str, const char* str_end) {
	size_t cnt = parseList(&symbolStorage,str,str_end-str);

	setupConnections(cnt);

	return true;
}
bool EmuUtils::SymbolTable::loadDeviceSymbolDumpFile(const char* path) {
	std::string fileStr;
	try {
		fileStr = StringUtils::loadFileIntoString(path); // (std::string("Cannot Open device symbol table dump File: ") + path).c_str()
	}
	catch (const std::runtime_error& e) {
		LU_LOGF_(LogUtils::LogLevel_Warning, "Cannot Open device symbol table dump file: \"%s\"", e.what());
		return false;
	}

	loadDeviceSymbolDump(fileStr.c_str(), fileStr.c_str()+fileStr.size());

	return true;
}

void EmuUtils::SymbolTable::resetAll() {
	symbolStorage.clear();
	symbsNameMap.clear();
	symbsIdMap.clear();
	sections.clear();

	symbolsRam.clear();
	symbolsRom.clear();

	maxRamAddrEnd = 0;
}


bool EmuUtils::SymbolTable::hasSymbols() const {
	return symbolStorage.size() > 0;
}

const EmuUtils::SymbolTable::Symbol::Section* EmuUtils::SymbolTable::getSection(const std::string& name) const {
	const auto& res = sections.find(name);
	if(res==sections.end()){
		return nullptr;
	}
	return &res->second;
}

const EmuUtils::SymbolTable::Symbol* EmuUtils::SymbolTable::getSymbolByName(const std::string& name) const {
	const auto& res = symbsNameMap.find(name);
	if (res == symbsNameMap.end())
		return nullptr;

	return getSymbolById(res->second);
}

const EmuUtils::SymbolTable::Symbol* EmuUtils::SymbolTable::getSymbolByValue(const symb_size_t value, const SymbolList& list) const {
	if (list.size() == 0)
		return nullptr;

	size_t from = 0;
	size_t to = list.size() - 1;
	while (from != to) {
		size_t mid = from + (to - from) / 2;
		symb_size_t val = getSymbol(list,mid)->value;
		if (val == value) {
			return getSymbol(list,mid);
		}
		else {
			if (val > value) {
				if (to == mid)
					break;
				to = mid;
			}
			else {
				if (from == mid)
					break;
				from = mid;
			}

		}
	}
	const Symbol* s = getSymbol(list,from);
	if (value >= s->value && value <= s->value + s->size)
		return s;
	return nullptr;
}

const EmuUtils::SymbolTable::Symbol* EmuUtils::SymbolTable::getSymbolById(uint32_t id) const {
	const auto& res = symbsIdMap.find(id);
	if (res == symbsIdMap.end()) {
		return nullptr;
	}
	return &symbolStorage[res->second];
}


const std::map<std::string, EmuUtils::SymbolTable::Symbol::Section>& EmuUtils::SymbolTable::getSections() const{
	return sections;
}

const EmuUtils::SymbolTable::Symbol* EmuUtils::SymbolTable::getSymbol(const SymbolList& symbs, size_t ind) const {
	return getSymbolById(symbs[ind]);
}
const EmuUtils::SymbolTable::SymbolList& EmuUtils::SymbolTable::getSymbols() const {
	return allSymbols;
}
const EmuUtils::SymbolTable::SymbolList& EmuUtils::SymbolTable::getSymbolsRam() const {
	return symbolsRam;
}
const EmuUtils::SymbolTable::SymbolList& EmuUtils::SymbolTable::getSymbolsRom() const {
	return symbolsRom;
}

const EmuUtils::SymbolTable::SymbolList* EmuUtils::SymbolTable::getSymbolsBySection(const std::string& section) const{
	auto res = symbolsBySections.find(section);
	if (res != symbolsBySections.end())
		return &res->second;
	return nullptr;
}

EmuUtils::SymbolTable::symb_size_t EmuUtils::SymbolTable::getMaxRamAddrEnd() const {
	return maxRamAddrEnd;
}

std::vector<std::pair<uint32_t, std::string>> EmuUtils::SymbolTable::getFuncSymbols() const {
	std::vector<std::pair<uint32_t, std::string>> res;

	const auto& symList = getSymbolsRom();
	for (size_t i = 0; i < symList.size(); i++) {
		const Symbol* symbol = getSymbol(symList, i);
		if(symbol->flags.scope & Symbol::Flags_Scope_Global || symbol->flags.funcFileObjectFlags & Symbol::Flags_FuncFileObj_Function)
			res.push_back({ (uint32_t)symbol->value, symbol->name });
	}

	return res;
}

std::pair<std::vector<std::tuple<std::string, uint32_t, uint32_t>>,std::vector<uint32_t>> EmuUtils::SymbolTable::getDataSymbolsAndDisasmSeeds() const {
	std::vector<std::tuple<std::string, uint32_t, uint32_t>> dataSymbs;
	std::vector<uint32_t> seeds;

	const auto* symList = getSymbolsBySection(".text");
	if(symList == nullptr) return { dataSymbs, seeds };

	for (size_t i = 0; i < symList->size(); i++) {
		const Symbol* symbol = getSymbol(*symList, i);

		if(symbol->size > 0 && symbol->flags.funcFileObjectFlags == Symbol::Flags_FuncFileObj_Obj) {
			dataSymbs.push_back({symbol->name, (uint32_t)symbol->value, (uint32_t)symbol->size});
		}
		else if(symbol->flags.scope & Symbol::Flags_Scope_Global || symbol->flags.funcFileObjectFlags & Symbol::Flags_FuncFileObj_Function) {
			seeds.push_back((uint32_t)symbol->value);
		}
	}

	// remove duplicates from seeds
	{
		size_t curr = 0;
		for (size_t i = 0; i < seeds.size();) {
			while (curr < dataSymbs.size() && std::get<1>(dataSymbs[curr]) < seeds[i]) {
				curr++;
			}

			if (curr >= dataSymbs.size())
				break;

			if (seeds[i] == std::get<1>(dataSymbs[curr])) {
				seeds.erase(seeds.begin() + i);
			}
			else {
				i++;
			}
		}
	}

	return { dataSymbs, seeds };
}


void EmuUtils::SymbolTable::getState(std::ostream& output){
	StreamUtils::write(output, symbolStorage.size());
	for(size_t i = 0; i<symbolStorage.size(); i++) {
		symbolStorage[i].getState(output);
	}

	StreamUtils::write(output, sections.size());
	for(auto& pair : sections) {
		StreamUtils::write(output, pair.first);
		StreamUtils::write(output, pair.second.name);
	}
}
void EmuUtils::SymbolTable::setState(std::istream& input){
	{
		size_t numSymbols;
		StreamUtils::read(input, &numSymbols);
		for(size_t i = 0; i<numSymbols; i++) {
			symbolStorage.push_back(Symbol());
			symbolStorage.back().setState(input);
		}
	}
	{
		size_t numSections;
		StreamUtils::read(input, &numSections);
		for(size_t i = 0; i<numSections; i++) {
			std::string key;
			std::string val;

			StreamUtils::read(input, &key);
			StreamUtils::read(input, &val);

			sections[key] = Symbol::Section(val);
		}
	}

	setupConnections(symbolStorage.size(), false);
}

void EmuUtils::SymbolTable::Symbol::getState(std::ostream& output){
	StreamUtils::write(output, value);

	StreamUtils::write(output, flags.scope);
	StreamUtils::write(output, flags.isWeak);
	StreamUtils::write(output, flags.isConstuctor);
	StreamUtils::write(output, flags.isWarning);
	StreamUtils::write(output, flags.indirectFlags);
	StreamUtils::write(output, flags.debugDynamicFlags);
	StreamUtils::write(output, flags.funcFileObjectFlags);

	StreamUtils::write(output, flagStr);
	StreamUtils::write(output, name);
	StreamUtils::write(output, demangled);
	StreamUtils::write(output, note);
	StreamUtils::write(output, size);
	StreamUtils::write(output, section);
	StreamUtils::write(output, id);
	StreamUtils::write(output, isHidden);
}
void EmuUtils::SymbolTable::Symbol::setState(std::istream& input){
	StreamUtils::read(input, &value);

	StreamUtils::read(input, &flags.scope);
	StreamUtils::read(input, &flags.isWeak);
	StreamUtils::read(input, &flags.isConstuctor);
	StreamUtils::read(input, &flags.isWarning);
	StreamUtils::read(input, &flags.indirectFlags);
	StreamUtils::read(input, &flags.debugDynamicFlags);
	StreamUtils::read(input, &flags.funcFileObjectFlags);

	StreamUtils::read(input, &flagStr);
	StreamUtils::read(input, &name);
	StreamUtils::read(input, &demangled);
	StreamUtils::read(input, &note);
	StreamUtils::read(input, &size);
	StreamUtils::read(input, &section);
	StreamUtils::read(input, &id);
	StreamUtils::read(input, &isHidden);
}

bool EmuUtils::SymbolTable::operator==(const SymbolTable& other) const{
#define _CMP_(x) (x==other.x)
	return _CMP_(symbolStorage) && _CMP_(sections) &&
		_CMP_(symbsIdMap) && _CMP_(symbsNameMap) && _CMP_(symbolsBySections) &&
		_CMP_(symbolsRam) && _CMP_(symbolsRom) &&
		_CMP_(maxRamAddrEnd);
#undef _CMP_
}

size_t EmuUtils::SymbolTable::Symbol::Section::sizeBytes() const {
	size_t sum = 0;

	sum += DataUtils::approxSizeOf(name);

	return sum;
}


size_t EmuUtils::SymbolTable::Symbol::sizeBytes() const {
	size_t sum = 0;

	sum += sizeof(value);
	sum += sizeof(flags);

	sum += DataUtils::approxSizeOf(flagStr);
	sum += DataUtils::approxSizeOf(name);
	sum += DataUtils::approxSizeOf(demangled);
	sum += DataUtils::approxSizeOf(note);

	sum += sizeof(hasDemangledName);

	sum += sizeof(size);

	sum += DataUtils::approxSizeOf(section);

	sum += sizeof(id);

	sum += sizeof(isHidden);

	sum += sizeof(extraData);

	return sum;
}

size_t EmuUtils::SymbolTable::sizeBytes() const {
	size_t sum = 0;

	sum += sizeof(symbolsAddDemanglFunc);
	sum += sizeof(symbolsAddDemanglFuncUserData);

	sum += DataUtils::approxSizeOf(symbolStorage);
	sum += DataUtils::approxSizeOf(sections);

	sum += DataUtils::approxSizeOf(symbsIdMap);
	sum += DataUtils::approxSizeOf(symbsNameMap);
	sum += DataUtils::approxSizeOf(symbolsBySections);

	sum += symbolsRam.capacity() * sizeof(symbolsRam[0]);
	sum += symbolsRom.capacity() * sizeof(symbolsRom[0]);

	sum += sizeof(maxRamAddrEnd);

	return sum;
}


// ##### utils #####

EmuUtils::SymbolTable::SymbolFeeder::SymbolFeeder(const SymbolTable* table, const SymbolList* list) : table(table), list(list) {

}

const EmuUtils::SymbolTable::Symbol* EmuUtils::SymbolTable::SymbolFeeder::getSymbol(symb_size_t addr) {
	if (!table || !list || curr >= list->size())
		return nullptr;

	const Symbol* symbol = nullptr;
	
	
	while (true) {
		symbol = table->getSymbol(*list, curr);

		if (curr+1 >= list->size() || (symbol->addrEnd() > addr && symbol->size > 0))
			break;

		curr++;
	}

	if (curr >= list->size())
		return nullptr;

	if (addr >= symbol->value && addr < symbol->addrEnd())
		return symbol;

	return nullptr;
}

/*

if (startStrOff == nullptr) {
//LogBackend::log(LogBackend::LogLevel_Warning, "could not read symbol table dump since it doesnt contain \"SYMBOL TABLE:\"");
//return false;
}

*/