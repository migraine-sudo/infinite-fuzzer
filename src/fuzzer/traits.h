#ifndef __TRAITS__
#define __TRAITS__

namespace traits{

	// 萃取类型，判断是否可以作为参数插入，用来协助实现不同架构下的ABI
	template<typename T> 
	struct is_insertable
	{
		static const bool value = std::is_integral<T>::value||std::is_floating_point<T>::value;
	};
	
	/*
	template<typename T>
	struct is_size_T
	{
		static const bool value = false;
	};
	template<>
	struct is_size_T<size_t>
	{
		static const bool value = true;
	};
	*/
}


#endif
