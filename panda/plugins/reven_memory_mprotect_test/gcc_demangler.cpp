//!
//! @file gcc_demangler.cpp
//! @brief Runtime defines `reven::util::gcc_demangler` and associated routines.
//!

#include "gcc_demangler.h"

#include <cassert>
#include <limits>

#include <dlfcn.h>

#include <sstream>

#include <cxxabi.h>

//!
//! @param mangled[in] Mangled identifier.
//! @param demangled[out] Where to store the demangled identifier.
//! @return The status of the demangling attempt.
//!
gcc_demangler::status gcc_demangler::demangle_name(const std::string& mangled, std::string& demangled)
{
	// Imported C++ symbols end with '@plt', which is not handled by the
	// low-level demangling mechanism. Thus, if the suffix is found in the mangled name,
	// demangle the symbol name without the '@plt' suffix, then add '@plt' back.

	constexpr char plt_suffix[] = "@plt";

	auto plt_location = mangled.find(plt_suffix);

	if (std::string::npos != plt_location) {
		auto status = demangle_abi_name(mangled.substr(0, plt_location), demangled);

		demangled.append(mangled.substr(plt_location));

		return status;
	} else {
		return demangle_abi_name(mangled, demangled);
	}
}

//!
//! @param[in] mangled The mangled identifier.
//! @return The demangled identifier on success, the mangled one otherwise.
//!
std::string gcc_demangler::demangle_name(const std::string& mangled)
{
	std::string demangled;

	auto state = demangle_name(mangled, demangled);

	return (state == status::success) ? demangled : mangled;
}

//!
//! @param[in] mangled A string containing the name to demangle.
//! @param[out] demangled Where to store the demangled identifier on success.
//! @return The status of the demangling attempt.
//!
//! @see [`abi::__cxa_demangle()` documentation]
//!
//! @todo Put back `RVN_ASSERT()` here rather than `assert()` calls.
//! @todo Consider wrapping the `result` pointer in a custom std::unique_ptr so that `free()` is called automatically;
//!   this would be exception-safe.
//! @todo Consider assign `demangled` with the mangled name on failure.
//!
//! [`abi::__cxa_demangle()` documentation]:
// http://gcc.gnu.org/onlinedocs/libstdc++/libstdc++-html-USERS-4.3/a01696.html
//!
//! @warning The implementation checks for the value of `RVN_HAVE_CXXABI_H` to detect whether demangling is possible.
//!   (using `abi::__cxa_demangle()`, provided by `<cxxabi.h>`). If `RVN_HAVE_CXXABI_H` is undefined, `demangled` is
//!   assigned the value of `mangled`, and `status::success` is returned.
//!
gcc_demangler::status gcc_demangler::demangle_abi_name(const std::string& mangled, std::string& demangled)
{
#if defined RVN_HAVE_CXXABI_H
	int code = std::numeric_limits<int>::max();

	char* result = abi::__cxa_demangle(mangled.c_str(), nullptr, nullptr, &code);

	assert((code >= -3) and (code <= 0));

	if (0 == code) {
		assert(nullptr != result);

		demangled = result;

		// The caller is responsible for deallocating this memory using free.
		free(result);
	}

	return static_cast<status>(code);
#else  // defined RVN_HAVE_CXXABI_H
	demangled = mangled;
	return status::success;
#endif // defined RVN_HAVE_CXXABI_H
}

//!
//! @param[in] address An opaque dynamic library handle.
//! @param[out] demangled Where to store the demangled identifier on success.
//! @return The status of the demangling attempt.
//!
//! @warning The implementation checks for the value of `RVN_HAVE_DLARR` to detect whether demangling the address can
//!   be done (using `dladdr()`). If `RVN_HAVE_DLADDR` is undefined, `demangled` is not altered, and
//!   `status::invalid_argument` is returned.
//!
gcc_demangler::status gcc_demangler::demangle_address(const void* address __attribute__((unused)),
                                                      std::string& demangled __attribute__((unused)))
{
#if defined RVN_HAVE_DLADDR
	using dynamic_library_info = Dl_info;

	dynamic_library_info dl_info;

	int result = dladdr(address, &dl_info);

	// Fail with error if an error occurs (no symbol matching address could be found).
	if ((0 == result) or (nullptr == dl_info.dli_sname)) {
		return status::invalid_argument;
	}

	return demangle_name(dl_info.dli_sname, demangled);
#else  // defined RVN_HAVE_DLADDR
	return status::invalid_argument;
#endif // defined RVN_HAVE_DLADDR
}

//!
//! @param[in] address An opaque dynamic library handle.
//! @return The demangled identifier on success, an empty string otherwise.
//!
std::string gcc_demangler::demangle_address(const void* address)
{
	std::string demangled;

	demangle_address(address, demangled);

	return demangled;
}
