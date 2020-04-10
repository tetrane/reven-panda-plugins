//!
//! @file demangler.h
//! @brief Declares `reven::util::demangler` and associated routines.
//!

#pragma once

#include <cstdint>
#include <string>

//!
//! @defgroup demangling Demangling
//! @ingroup utilities
//!
//! Transform C++ ABI identifiers into original C++ source identifiers.
//!
//! The class `gcc_demangler` provides services to demangle gcc C++ ABI identifiers, with various input possibilities.
// The family
//! of routines `demangle()` are shortcuts to use the `demangler` object.
//!

//!
//! @addtogroup demangling
//! @{
//!

//!
//! @brief Provide services to transform C++ ABI identifiers like RTTI symbols into the original C++ source identifiers.
//!
//! Example:
//!
//! ~~~.cpp
//! struct base {};
//! struct derived: base {};
//! std::unique_ptr<base> d = new derived;
//! std::cout << reven::util::gcc_demangler::demangle_instance(*d) << std::endl;
//! ~~~
//!
//! @class gcc_demangler gcc_demangler.h <util/gcc_demangler.h>
//!
class gcc_demangler {
public:
	//! The possible outcomes of demangling attempts.
	enum class status : std::int8_t {
		//! The demangling operation succeeded.
		success = 0,

		//! A memory allocation failure occured.
		memory_failure = -1,

		//! The mangled name provided is not a valid name under the C++ ABI
		//! mangling rules.
		invalid_mangle = -2,

		//! One of the arguments is invalid.
		invalid_argument = -3,
	};

	//! Provides the demangled identifier of a mangled one.
	status demangle_name(const std::string& mangled, std::string& demangled);

	//! Provides the demangled identifier of a mangled one.
	std::string demangle_name(const std::string& mangled);

	//! Provides the demangled name of a type.
	template <typename Type> status demangle_type(std::string& demangled);

	//! Provides the demangled name of a type.
	template <typename Type> std::string demangle_type();

	//! Provides the demangled name of an instance.
	template <typename Type> status demangle_instance(const Type& instance, std::string& demangled);

	//! Provides the demangled name of an instance.
	template <typename Type> std::string demangle_instance(const Type& instance);

	//! Provides the demangled name residing at the specified address, given an opaque dynamic library handle.
	status demangle_address(const void* address, std::string& demangled);

	//! Provides the demangled name residing at the specified address, given an opaque dynamic library handle.
	std::string demangle_address(const void* address);

private:
	//! Generates the demangled name of a mangled symbol and returns the resulting status.
	status demangle_abi_name(const std::string& mangled, std::string& demangled);

}; // class demangler

//! Provides the demangled identifier of a mangled one.
std::string demangle_gcc(const std::string& mangled);

//! Provides the demangled identifier of a mangled one.
std::string demangle_gcc(const char mangled[]);

//! Provides the demangled name residing at the specified address, given an opaque dynamic library handle.
std::string demangle_gcc(const void* address);

//! Provides the demangled name of a type.
template <typename Type> std::string demangle_gcc();

//! Provides the demangled name of an instance.
template <typename Type> std::string demangle_gcc(const Type& instance);


#include "gcc_demangler_impl.h"
