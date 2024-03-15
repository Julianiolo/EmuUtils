#include "ElfReader.h"

#include <cstring>
#include <algorithm>

#include "StringUtils.h"
#include "DataUtils.h"
#include "LogUtils.h"
#include "DataUtilsSize.h"


#define LU_MODULE "ELF"

uint8_t EmuUtils::ELF::ELFFile::SymbolTableEntry::getInfoBinding() const {
	return info >> 4;
}
uint8_t EmuUtils::ELF::ELFFile::SymbolTableEntry::getInfoType() const {
	return info & 0xf;
}

bool EmuUtils::ELF::ELFFile::DWARF::_debug_line::File::operator==(const File& f) {
	return name == f.name && dir == f.dir && time == f.time && size == f.size;
}

EmuUtils::ELF::ELFFile::DWARF::_debug_line::CU::Header EmuUtils::ELF::ELFFile::DWARF::_debug_line::parseCUHeader(ByteStreamReader* stream) {
	CU::Header header;

	header.length                 = (uint32_t)stream->getInt(4);
	header.version                = (uint16_t)stream->getInt(2);
	header.header_length          = (uint32_t)stream->getInt(4);
	header.min_instruction_length = stream->getByte();
	header.default_is_stmt        = stream->getByte();
	header.line_base              = stream->getByte();
	header.line_range             = stream->getByte();
	header.opcode_base            = stream->getByte();
	stream->read(header.std_opcode_lengths, sizeof(header.std_opcode_lengths));

	return header;
}
std::vector<EmuUtils::ELF::ELFFile::DWARF::_debug_line::CU::Entry> EmuUtils::ELF::ELFFile::DWARF::_debug_line::parseLineByteCode(ByteStreamReader* stream, CU* cu, _debug_line* dl) {
	std::vector<CU::Entry> entrys;
	
	// state machine vars
	uint64_t address = 0;
	uint32_t file = 1;
	uint32_t line = 1;
	uint32_t column = 0; // starts at 1
	bool is_stmt = cu->header.default_is_stmt;
	bool basic_block = false;
	bool end_sequence = false;
	

	const uint32_t const_pc_add = 245 / cu->header.line_range;

	while (stream->hasLeft()) {
		uint8_t opcode = stream->getByte();
		if (opcode < cu->header.opcode_base) {
			switch (opcode) {
				case DW_LNS_extended_op: 
				{
					uint64_t insn_len = getUleb128(stream);
					opcode = stream->getByte();
					switch (opcode) {
						case DW_LNE_end_sequence:
							end_sequence = true;
							entrys.push_back(CU::Entry{ address, file, line-1, column });
							address = 0;
							file = 1;
							line = 1;
							column = 0; // starts at 1
							is_stmt = cu->header.default_is_stmt;
							basic_block = false;
							end_sequence = false;
							break;
						case DW_LNE_set_address:
							address = stream->getInt(4);
							break;

						case DW_LNE_define_file:
						{
							File filedef;
							filedef.name = stream->readStr();
							uint32_t dir = (uint32_t)getUleb128(stream) - 1;
							filedef.time = (uint32_t)getUleb128(stream);
							filedef.size = (uint32_t)getUleb128(stream);

							filedef.dir = dir != (uint32_t)-1 ? (uint32_t)cu->dirs[dir] : -1;

							size_t pos = -1;
							for (size_t i = 0; i < dl->files.size(); i++) {
								if (filedef == dl->files[i]) {
									pos = i;
									break;
								}
							}

							if (pos == (size_t)-1) {
								dl->files.push_back(filedef);
								pos = dl->files.size() - 1;
							}

							cu->files.push_back(pos);
							break;
						}
							
						default:
							stream->advance(insn_len);
							break;
					}
					break; //???
				}

				case DW_LNS_copy:
				{
					entrys.push_back(CU::Entry{ address, file, line-1, column });
					basic_block = false;
					break;
				}


				case DW_LNS_advance_pc:
				{
					uint64_t amt = getUleb128(stream);
					address += amt * cu->header.min_instruction_length;
					break;
				}


				case DW_LNS_advance_line:
				{
					int64_t amt = getSleb128(stream);
					line += (int32_t)amt;
					break;
				}

				case DW_LNS_set_file:
					file = (uint32_t)(getUleb128(stream) - 1);
					break;

				case DW_LNS_set_column:
					column = (uint32_t)getUleb128(stream);
					break;

				case DW_LNS_negate_stmt:
					is_stmt = !is_stmt;
					break;

				case DW_LNS_set_basic_block:
					basic_block = true;
					break;

				case DW_LNS_const_add_pc:
					address += const_pc_add;
					break;

				case DW_LNS_fixed_advance_pc:
				{
					uint16_t amt = (uint16_t)stream->getInt(2);
					address += amt;
					break;
				}
			}

		}
		else {
			// special opcodes
			int adj = opcode - cu->header.opcode_base;
			int addr_adv = adj / cu->header.line_range;
			int line_adv = cu->header.line_base + (adj % cu->header.line_range);

			addr_adv &= 0xff;
			line_adv &= 0xff;

			address += addr_adv;
			line += line_adv;
			basic_block = false;

			entrys.push_back(CU::Entry{ address, file, line-1, column });
		}
	}

	return entrys;
}

EmuUtils::ELF::ELFFile::DWARF::_debug_line::CU::Entry* EmuUtils::ELF::ELFFile::DWARF::_debug_line::getEntry(size_t ind) {
	const auto& indexes = entrys[ind];
	return &cus[indexes.first].entrys[indexes.second];
}
const EmuUtils::ELF::ELFFile::DWARF::_debug_line::CU::Entry* EmuUtils::ELF::ELFFile::DWARF::_debug_line::getEntry(size_t ind) const {
	const auto& indexes = entrys[ind];
	return &cus[indexes.first].entrys[indexes.second];
}

size_t EmuUtils::ELF::ELFFile::DWARF::_debug_line::getNumEntrys() const {
	return entrys.size();
}

size_t EmuUtils::ELF::ELFFile::DWARF::_debug_line::getEntryIndByAddr(uint64_t addr) {
	if (entrys.size() == 0)
		return -1;
	
	size_t from = 0;
	size_t to = entrys.size() - 1;

	size_t ind;

	while (from != to) {
		size_t mid = from + (to-from) / 2;

		CU::Entry* entry = getEntry(mid);

		if (entry->addr == addr) {
			ind = mid;
			goto success;
		}
		else if (entry->addr > addr) {
			if (mid == to)
				goto fail;
			to = mid;
		}
		else {
			if (mid == from)
				goto fail;
			from = mid;
		}
	}

	if (getEntry(from)->addr == addr){
		ind = from;
		goto success;
	}

fail:
	return -1;

success:
	while(ind > 0 && getEntry(ind-1)->addr == addr)
		ind--;

	return ind;
}

EmuUtils::ELF::ELFFile::DWARF::_debug_line EmuUtils::ELF::ELFFile::DWARF::parse_debug_line(const uint8_t* data, size_t dataLen, const ELFHeader::Ident& ident) {
	_debug_line lines;
	lines.couldFind = true;

	bool lsb = ident.dataEncoding == ELFFile::ELFHeader::Ident::DataEncoding_LSB;

	lines.dirs.clear();
	lines.files.clear();

	ByteStreamReader stream(data, dataLen, lsb);

	while (stream.hasLeft()) {
		size_t begin = stream.getOff();

		_debug_line::CU cu;
		cu.header = _debug_line::parseCUHeader(&stream);
		//stream.advance(1); //??
		size_t end         = begin + 4 + cu.header.length;
		size_t prologueEnd = begin + 4 + 2 + 4 + cu.header.header_length;

		if (cu.header.version != 2 || cu.header.opcode_base != 10) { // not valid dwarf2 
			LU_LOGF_(LogUtils::LogLevel_Warning, "Not valid DWARF2 @%" CU_PRIuSIZE, begin);
			stream.goTo(end);
			continue;
		}

		// extract dirs
		cu.dirs.clear();
		stream.setLen(prologueEnd);
		while (stream.hasLeft()) {
			std::string_view dirStr = stream.readStr();

			if (dirStr.size() == 0) // found termination
				break;

			size_t pos = -1;
			for (size_t i = 0; i < lines.dirs.size(); i++) {
				if (lines.dirs[i] == dirStr) {
					pos = i;
					break;
				}
			}
			if (pos == (size_t)-1) {
				lines.dirs.push_back(std::string(dirStr));
				pos = lines.dirs.size() - 1;
			}
			cu.dirs.push_back(pos);
		}

		// extract files
		while (stream.hasLeft()) {
			std::string_view name = stream.readStr();

			if (name.size() == 0) // found termination
				break;

			_debug_line::File file;
			file.name = name;

			uint32_t dir = (uint32_t)getUleb128(&stream) - 1; // index
			file.time    = (uint32_t)getUleb128(&stream);
			file.size    = (uint32_t)getUleb128(&stream);

			file.dir = (uint32_t)cu.dirs[dir]; // convert to global merged dir index

			size_t pos = -1;

			for (size_t i = 0; i < lines.files.size(); i++) {
				if (file == lines.files[i]) {
					pos = i;
					break;
				}
			}

			if(pos == (size_t)-1){
				lines.files.push_back(file);
				pos = lines.files.size() - 1;
			}
			cu.files.push_back(pos);
		}

		cu.section = {prologueEnd+1, end-stream.getOff()};

		stream.setLen(end);
		cu.entrys = _debug_line::parseLineByteCode(&stream, &cu, &lines);
		
		// add Entrys to global Entrys
		for (size_t i = 0; i < cu.entrys.size(); i++) {
			lines.entrys.push_back({ (uint32_t)lines.cus.size(), i });
		}

		stream.setLen(dataLen);
		stream.goTo(end);

		lines.cus.push_back(cu);
	}

	std::sort(lines.entrys.begin(), lines.entrys.end(), [&](const std::pair<uint32_t, size_t>& a, const std::pair<uint32_t, size_t>& b) {
		return lines.cus[a.first].entrys[a.second].addr < lines.cus[b.first].entrys[b.second].addr;
	});

	for (size_t i = 0; i < lines.files.size(); i++) {
		_debug_line::File& file = lines.files[i];
		file.couldFind = false;

		const std::string& dir = lines.dirs[file.dir];
		std::string path = dir + "/" + file.name;

		if (StringUtils::fileExists(path.c_str())) {
			try {
				file.content = StringUtils::loadFileIntoString(path.c_str());
				file.couldFind = true;
			}
			catch (const std::runtime_error&) {
				file.couldFind = false;
			}
		}

		if(file.couldFind)
			LU_LOGF_(LogUtils::LogLevel_DebugOutput, "Loaded File \"%s\" from %s", file.name.c_str(), dir.c_str());
		else
			LU_LOGF_(LogUtils::LogLevel_DebugOutput, "Coudn't load File \"%s\" from %s", file.name.c_str(), dir.c_str());
		
		if(file.couldFind)
			file.lines = StringUtils::generateLineIndexArr(file.content.c_str());
	}

	return lines;
}

uint64_t EmuUtils::ELF::ELFFile::DWARF::getUleb128(ByteStreamReader* stream) {
	uint64_t val = 0;
	uint8_t shift = 0;

	while (true) {
		uint8_t b = stream->getByte();
		val |= (uint64_t)(b & 0x7f) << shift;
		if ((b & 0x80) == 0)
			break;
		shift += 7;
	}

	return val;
}
int64_t EmuUtils::ELF::ELFFile::DWARF::getSleb128(ByteStreamReader* stream) {
	int64_t val = 0;
	uint8_t shift = 0;
	uint32_t size = 8 << 3;

	uint8_t b;
	while (true) {
		b = stream->getByte();
		val |= (uint64_t)(b & 0x7f) << shift;
		shift += 7;
		if ((b & 0x80) == 0)
			break;
	}

	if (shift < size && (b & 0x40) != 0)
		val |= -(1 << shift);

	return val;
}

EmuUtils::ELF::ELFFile::DWARF EmuUtils::ELF::parseDWARF(const ELFFile& elf) {
	ELFFile::DWARF dwarf;
	size_t debug_line_ind = -1;
	for (size_t i = 0; i < elf.sectionHeaders.size(); i++) {
		if (std::strcmp(elf.shstringTableStr + elf.sectionHeaders[i].name, ".debug_line") == 0) {
			debug_line_ind = i;
			break;
		}
	}

	if (debug_line_ind != (size_t)-1) {
		dwarf.debug_line = ELFFile::DWARF::parse_debug_line(&elf.data[0] + elf.sectionContents[debug_line_ind].first, elf.sectionContents[debug_line_ind].second, elf.header.ident);
	}

	return dwarf;
}


uint64_t EmuUtils::ELF::intFromByteArr(const uint8_t* data, uint8_t byteLen, bool lsb) {
	uint64_t out = 0;
	if (!lsb) {
		for (size_t i = 0; i < byteLen; i++) {
			out <<= 8;
			out |= data[i];
		}
	}
	else {
		for (size_t i = 0; i < byteLen; i++) {
			out <<= 8;
			out |= data[byteLen - 1 - i];
		}
	}
	return out;
}
uint64_t EmuUtils::ELF::intFromByteArrAdv(const uint8_t** data, uint8_t byteLen, bool lsb) {
	uint64_t res = intFromByteArr(*data, byteLen, lsb);
	(*data) += byteLen;
	return res;
}

EmuUtils::ELF::ELFFile::ELFHeader::Ident EmuUtils::ELF::parseELFHeaderIdentification(ByteStreamReader* stream) {
	ELFFile::ELFHeader::Ident ident;

	stream->read(ident.magic, 4);
	if (std::memcmp(ident.magic, "\x7f" "ELF", 4) != 0) {
		throw std::runtime_error("Elf file does not have magic!");
	}

	ident.classtype    = stream->getByte();
	ident.dataEncoding = stream->getByte();
	ident.version      = stream->getByte();
	ident.OSABI        = stream->getByte();
	ident.ABIVersion   = stream->getByte();

	stream->advance(7); // padding

	return ident;
}

EmuUtils::ELF::ELFFile::ELFHeader EmuUtils::ELF::parseELFHeader(ByteStreamReader* stream) {
	ELFFile::ELFHeader header;

	if (!stream->canReadAmt(ELFFile::ELFHeader::Ident::byteSize)) {
		throw std::runtime_error("Not enough bytes for ELF Header");
	}

	header.ident = parseELFHeaderIdentification(stream);

	bool is64Bit = header.ident.classtype == ELFFile::ELFHeader::Ident::ClassType_64Bit;
	uint8_t addrSize = is64Bit ? 8 : 4;
	{
		size_t headerLenRem = 2 + 2 + 4 + addrSize + addrSize + addrSize + 4 + 2 + 2 + 2 + 2 + 2 + 2;
		if (!stream->canReadAmt(headerLenRem)) {
			throw std::runtime_error("Not enough bytes for ELF Header");
		}
	}
	bool lsb = header.ident.dataEncoding == ELFFile::ELFHeader::Ident::DataEncoding_LSB;
	stream->setIsLsbFirst(lsb);

	header.type      = (ELFFile::HalfWord) stream->getInt(2);
	header.machine   = (ELFFile::HalfWord) stream->getInt(2);

	header.version   = (ELFFile::Word)     stream->getInt(4);

	header.entry     = (ELFFile::Word)     stream->getInt(addrSize);
	header.phoff     = (ELFFile::Word)     stream->getInt(addrSize);
	header.shoff     = (ELFFile::Word)     stream->getInt(addrSize);

	header.flags     = (ELFFile::Word)     stream->getInt(4);

	header.ehsize    = (ELFFile::HalfWord) stream->getInt(2);
	header.phentsize = (ELFFile::HalfWord) stream->getInt(2);
	header.phnum     = (ELFFile::HalfWord) stream->getInt(2);
	header.shentsize = (ELFFile::HalfWord) stream->getInt(2);
	header.shnum     = (ELFFile::HalfWord) stream->getInt(2);
	header.shstrndx  = (ELFFile::HalfWord) stream->getInt(2);

	return header;
}


EmuUtils::ELF::ELFFile::ProgramHeader EmuUtils::ELF::parseELFProgramHeader(ByteStreamReader* stream, const ELFFile::ELFHeader::Ident& ident) {
	ELFFile::ProgramHeader header;

	bool is64Bit = ident.classtype == ELFFile::ELFHeader::Ident::ClassType_64Bit;
	uint8_t addrSize = is64Bit ? 8 : 4;

	header.type      = (ELFFile::Word)    stream->getInt(4);

	if (is64Bit) {
		header.flags = (ELFFile::Word)    stream->getInt(4);
	}

	header.offset    = (ELFFile::Offset)  stream->getInt(addrSize);

	header.vaddr     = (ELFFile::Address) stream->getInt(addrSize);
	header.paddr     = (ELFFile::Address) stream->getInt(addrSize);

	header.filesz    = (ELFFile::Word)    stream->getInt(4);
	header.memsz     = (ELFFile::Word)    stream->getInt(4);
	if (!is64Bit) {
		header.flags = (ELFFile::Word)    stream->getInt(4);
	}
	header.align     = (ELFFile::Word)    stream->getInt(4);

	return header;
}

EmuUtils::ELF::ELFFile::SectionHeader EmuUtils::ELF::parseELFSectionHeader(ByteStreamReader* stream, const ELFFile::ELFHeader::Ident& ident) {
	ELFFile::SectionHeader header;

	bool is64Bit = ident.classtype == ELFFile::ELFHeader::Ident::ClassType_64Bit;
	uint8_t addrSize = is64Bit ? 8 : 4;


	header.name      = (ELFFile::Word)    stream->getInt(4);
	header.type      = (ELFFile::Word)    stream->getInt(4);
	header.flags     = (ELFFile::Word)    stream->getInt(4);

	header.addr      = (ELFFile::Address) stream->getInt(addrSize);
	header.offset    = (ELFFile::Offset)  stream->getInt(addrSize);

	header.size      = (ELFFile::Word)    stream->getInt(4);
	header.link      = (ELFFile::Word)    stream->getInt(4);
	header.info      = (ELFFile::Word)    stream->getInt(4);
	header.addralign = (ELFFile::Word)    stream->getInt(4);
	header.entsize   = (ELFFile::Word)    stream->getInt(4);

	return header;
}

EmuUtils::ELF::ELFFile::SymbolTableEntry EmuUtils::ELF::parseELFSymbol(ByteStreamReader* stream, const ELFFile::ELFHeader::Ident& ident) {
	ELFFile::SymbolTableEntry symb;

	bool is64Bit = ident.classtype == ELFFile::ELFHeader::Ident::ClassType_64Bit;
	uint8_t addrSize = is64Bit ? 8 : 4;

	symb.name  = (ELFFile::Word)     stream->getInt(4);
	symb.value = (ELFFile::Address)  stream->getInt(addrSize);
	symb.size  = (ELFFile::Word)     stream->getInt(4);

	symb.info  = stream->getByte();
	symb.other = stream->getByte();

	symb.shndx = (ELFFile::HalfWord) stream->getInt(2);

	return symb;
}

EmuUtils::ELF::ELFFile EmuUtils::ELF::parseELFFile(const uint8_t* data, size_t dataLen) {
	ELFFile file;
	file.data.resize(dataLen);
	std::memcpy(&file.data[0], data, dataLen);
	ByteStreamReader stream(&file.data[0], dataLen);

	file.header = parseELFHeader(&stream);

	for (size_t i = 0; i < file.header.phnum; i++) {
		size_t off = file.header.phoff + i * file.header.phentsize;
		stream.goTo(off);

		ELFFile::ProgramHeader ph = parseELFProgramHeader(&stream, file.header.ident);


		file.segmentContents.push_back({ph.offset, ph.filesz});
		file.programHeaders.push_back(ph);
	}

	for (size_t i = 0; i < file.header.shnum; i++) {
		{
			size_t off = file.header.shoff + i * file.header.shentsize;
			stream.goTo(off);
		}
		
		ELFFile::SectionHeader sh = parseELFSectionHeader(&stream, file.header.ident);

		if (sh.type == ELFFile::SectionHeader::Type_SHT_SYMTAB) {
			size_t numEntrys = sh.size / sh.entsize;
			for (size_t i = 0; i < numEntrys; i++) {
				size_t off = sh.offset + i * sh.entsize;
				stream.goTo(off);

				ELFFile::SymbolTableEntry symb = parseELFSymbol(&stream, file.header.ident);

				file.symbolTableEntrys.push_back(symb);
			}
		}
		else if (sh.type == ELFFile::SectionHeader::Type_SHT_STRTAB) {
			if(i == file.header.shstrndx)
				file.shstringTableStr = (const char*)&file.data[0] + sh.offset;
			else
				file.stringTableStr = (const char*)&file.data[0] + sh.offset;
		}

		file.sectionContents.push_back({sh.offset, sh.size});
		file.sectionHeaders.push_back(sh);
	}

	file.dwarf = parseDWARF(file);

	return file;
}

size_t EmuUtils::ELF::ELFFile::getIndOfSectionWithName(const char* name) const {
	for (size_t i = 0; i < sectionHeaders.size(); i++) {
		if (strcmp(shstringTableStr + sectionHeaders[i].name, name) == 0) {
			return i;
		}
	}
	return -1;
}

bool EmuUtils::ELF::ELFFile::hasInfosLoaded() const {
	return data.size() > 0;
}

size_t EmuUtils::ELF::ELFFile::DWARF::_debug_line::CU::sizeBytes() const {
	size_t sum = 0;

	sum += sizeof(header);

	sum += DataUtils::approxSizeOf(section);

	sum += DataUtils::approxSizeOf(dirs);
	sum += DataUtils::approxSizeOf(files);

	sum += DataUtils::approxSizeOf(entrys);

	return sum;
}
size_t EmuUtils::ELF::ELFFile::DWARF::_debug_line::File::sizeBytes() const {
	size_t sum = 0;

	sum += DataUtils::approxSizeOf(name);
	sum += sizeof(dir);
	sum += sizeof(time);
	sum += sizeof(size);

	sum += sizeof(couldFind);
	sum += DataUtils::approxSizeOf(content);
	sum += DataUtils::approxSizeOf(lines);

	return sum;
}
size_t EmuUtils::ELF::ELFFile::DWARF::_debug_line::sizeBytes() const {
	size_t sum = 0;

	sum += sizeof(couldFind);

	sum += DataUtils::approxSizeOf(cus);

	sum += DataUtils::approxSizeOf(dirs);

	sum += DataUtils::approxSizeOf(entrys);

	sum += DataUtils::approxSizeOf(files);

	return sum;
}
size_t EmuUtils::ELF::ELFFile::DWARF::sizeBytes() const {
	size_t sum = 0;

	sum += debug_line.sizeBytes();

	return sum;
}
size_t EmuUtils::ELF::ELFFile::sizeBytes() const {
	size_t sum = 0;

	sum += dwarf.sizeBytes();

	sum += DataUtils::approxSizeOf(data);
	sum += sizeof(dataLen);

	sum += sizeof(header);
	sum += DataUtils::approxSizeOf(programHeaders);
	sum += DataUtils::approxSizeOf(segmentContents);
	sum += DataUtils::approxSizeOf(sectionHeaders);
	sum += DataUtils::approxSizeOf(sectionContents);

	sum += DataUtils::approxSizeOf(symbolTableEntrys);
	sum += sizeof(stringTableStr);
	sum += sizeof(shstringTableStr);

	return sum;
}


std::vector<uint8_t> EmuUtils::ELF::getProgramData(const ELF::ELFFile& elf) {
	size_t textInd = elf.getIndOfSectionWithName(".text");
	size_t dataInd = elf.getIndOfSectionWithName(".data");

	if (textInd != (size_t)-1 && dataInd != (size_t)-1) {
		size_t len = elf.sectionContents[textInd].second + elf.sectionContents[dataInd].second;
		std::vector<uint8_t> res(len);

		std::memcpy(&res[0], &elf.data[0] + elf.sectionContents[textInd].first, elf.sectionContents[textInd].second);
		std::memcpy(&res[0] + elf.sectionContents[textInd].second, &elf.data[0] + elf.sectionContents[dataInd].first, elf.sectionContents[dataInd].second);

		LU_LOG_(LogUtils::LogLevel_DebugOutput, "Successfully loaded ProgramData from elf!");
		return res;
	}
	else {
		LU_LOGF_(LogUtils::LogLevel_Error, "Couldn't find required sections for execution: %s %s", textInd == (size_t)-1 ? ".text" : "", dataInd == (size_t)-1 ? ".data" : "");
		return {};
	}
}

std::vector<std::pair<uint32_t, std::string>> EmuUtils::ELF::genSourceSnippets(const ELF::ELFFile& elf) {
	std::vector<std::pair<uint32_t, std::string>> res;

	for (size_t i = 0; i < elf.dwarf.debug_line.getNumEntrys(); i++) {
		auto entry = elf.dwarf.debug_line.getEntry(i);
		if (entry->file == (decltype(entry->file))-1) continue; // skip if no file available


		const auto& file = elf.dwarf.debug_line.files[entry->file];
		if (!file.couldFind) continue;
		if (entry->line >= file.lines.size()) {
			LU_LOGF_(LogUtils::LogLevel_Warning, "line num too big: %u for file %s (%u) [@%u]", entry->line, file.name.c_str(), file.lines.size(), entry->addr);
			continue; // should not happen but can happen if wrong file
		}
		

		size_t lineFrom = entry->line;
#if 1
		if (i > 0) {
			auto lastEntry = elf.dwarf.debug_line.getEntry(i-1);
			if (lastEntry->file == entry->file && lastEntry->line+1 < entry->line) {
				lineFrom = lastEntry->line+1;
			}
		}
#endif
		const size_t lineTo = entry->line + 1;

		if (lineTo - lineFrom > 5)
			lineFrom = lineTo - 5;

		const size_t charFrom = file.lines[lineFrom];
		const size_t charTo = ((lineTo < file.lines.size()) ? file.lines[lineTo]-1 : file.content.size());

		if (res.size() == 0 || res.back().first != entry->addr)
			res.push_back({ (uint32_t)entry->addr, "" });

		if (res.back().second.size() != 0)
			res.back().second += "\n";
		//res.back().second += std::string(file.content.c_str() + charFrom, file.content.c_str() + charTo);
		res.back().second += StringUtils::format("%-100s [[%s:%u-%u]]", std::string(file.content.c_str() + charFrom, file.content.c_str() + charTo).c_str(), file.name.c_str(), lineFrom, lineTo);
	}
	return res;
}



/*



uint64_t base_address = 0;
uint64_t fileno = 0, lineno = 1;
uint64_t prev_fileno = 0, prev_lineno = 1;
std::string define_file = "";
uint64_t min_address = -1, max_address = 0;




*/