#include "fpcap/filesystem/writing/FileWriter.hpp"

namespace fpcap {

FileWriter::FileWriter(const std::string& filepath) : mFilepath(filepath) {}

FileWriter::~FileWriter() {}

} // namespace fpcap
