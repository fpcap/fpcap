#include "fpcap/filesystem/FileWriter.hpp"

namespace fpcap {

FileWriter::FileWriter(const std::string& filepath) : mFilepath(filepath) {}

FileWriter::~FileWriter() {}

} // namespace fpcap
