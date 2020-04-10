//!
//! @file gcc_demangler_impl.h
//! @brief Compile-time defines `reven::util::gcc_demangler` and associated routines.
//!

#pragma once

#include <typeinfo>

//!
//! @param[out] demangled Where to store the demangled identifier on success.
//! @return The status of the demangling attempt.
//!
//! @tparam Type Type to generate demangled name from.
//!
template <typename Type> inline gcc_demangler::status gcc_demangler::demangle_type(std::string& demangled)
{
	return demangle_name(typeid(Type).name(), demangled);
}

//!
//! @return The demangled name of Type if available, its mangled name otherwise.
//!
//! @tparam Type Type to generate demangled name from.
//!
template <typename Type> inline std::string gcc_demangler::demangle_type()
{
	return demangle_name(typeid(Type).name());
}

//!
//! @param[in] instance Instance to generate demangled name from.
//! @param[out] demangled Where to store the demangled identifier on success.
//! @return The status of the demangling attempt.
//!
//! @tparam Type type to the instance (_auto. deduced_).
//!
template <typename Type>
inline gcc_demangler::status gcc_demangler::demangle_instance(const Type& instance, std::string& demangled)
{
	return demangle_name(typeid(instance).name(), demangled);
}

//!
//! @param[in] instance Instance to generate demangled name from.
//! @return The demangled name of Type if available, its mangled name otherwise.
//!
//! @tparam Type Type of the instance (_auto. deduced_).
//!
template <typename Type> inline std::string gcc_demangler::demangle_instance(const Type& instance)
{
	return demangle_name(typeid(instance).name());
}

//!
//! @param[in] mangled Mangled identifier.
//! @return The demangled identifier on success, the mangled one otherwise.
//!
inline std::string demangle_gcc(const std::string& mangled)
{
	return gcc_demangler().demangle_name(mangled);
}

//!
//! @param[in] mangled Mangled identifier.
//! @return The demangled identifier on success, the mangled one otherwise.
//!
inline std::string demangle_gcc(const char mangled[])
{
	return gcc_demangler().demangle_name(std::string(mangled));
}

//!
//! @param[in] address An opaque dynamic library handle.
//! @return The demangled identifier on success, the mangled one otherwise.
//!
inline std::string demangle_gcc(const void* address)
{
	return gcc_demangler().demangle_address(address);
}

//!
//! @return The demangled name of Type if available, its mangled name otherwise.
//!
//! @tparam Type Type to generate demangled name from.
//!
template <typename Type> inline std::string demangle_gcc()
{
	return gcc_demangler().demangle_type<Type>();
}

//!
//! @param[in] instance Instance to generate demangled name from.
//! @return The demangled name of Type if available, its mangled name otherwise.
//!
//! @tparam Type type to the instance (_auto. deduced_).
//!
template <typename Type> inline std::string demangle_gcc(const Type& instance)
{
	return gcc_demangler().demangle_instance(instance);
}
