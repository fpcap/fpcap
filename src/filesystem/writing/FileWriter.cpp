#include "mmpr/filesystem/writing/FileWriter.hpp"

namespace mmpr {

FileWriter::FileWriter(const std::string& filepath) : mFilepath(filepath) {}

FileWriter::~FileWriter() {}

} // namespace mmpr
