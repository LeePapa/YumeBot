﻿#ifndef JCE_STRUCT
#	define JCE_STRUCT(name, alias)
#endif

#ifndef JCE_STRUCT_DEFAULT_ALIAS
#	define JCE_STRUCT_DEFAULT_ALIAS(name) JCE_STRUCT(name, #  name)
#endif

#ifndef END_JCE_STRUCT
#	define END_JCE_STRUCT(name)
#endif

#ifndef NO_OP
#	define NO_OP
#endif

#ifndef DEFAULT_INITIALIZER
#	define DEFAULT_INITIALIZER(...) NO_OP
#endif

#ifndef IS_OPTIONAL
#	define IS_OPTIONAL(defaultValue) NO_OP
#endif

#ifndef TEMPLATE_ARGUMENT
#	define TEMPLATE_ARGUMENT(...) NO_OP
#endif

#ifndef FIELD
#	define FIELD(name, tag, type, ...)
#endif

#ifndef BYTE
#	define BYTE(name, tag, ...) FIELD(name, tag, Byte, __VA_ARGS__)
#endif

#ifndef SHORT
#	define SHORT(name, tag, ...) FIELD(name, tag, Short, __VA_ARGS__)
#endif

#ifndef INT
#	define INT(name, tag, ...) FIELD(name, tag, Int, __VA_ARGS__)
#endif

#ifndef LONG
#	define LONG(name, tag, ...) FIELD(name, tag, Long, __VA_ARGS__)
#endif

#ifndef FLOAT
#	define FLOAT(name, tag, ...) FIELD(name, tag, Float, __VA_ARGS__)
#endif

#ifndef DOUBLE
#	define DOUBLE(name, tag, ...) FIELD(name, tag, Double, __VA_ARGS__)
#endif

#ifndef STRING1
#	define STRING1(name, tag, ...) FIELD(name, tag, String1, __VA_ARGS__)
#endif

#ifndef STRING4
#	define STRING4(name, tag, ...) FIELD(name, tag, String4, __VA_ARGS__)
#endif

#ifndef MAP
#	define MAP(name, tag, ...) FIELD(name, tag, Map, __VA_ARGS__)
#endif

#ifndef LIST
#	define LIST(name, tag, ...) FIELD(name, tag, List, __VA_ARGS__)
#endif

#ifndef STRUCT
#	define STRUCT(name, tag, ...) FIELD(name, tag, StructBegin, __VA_ARGS__)
#endif

#ifndef ZERO_TAG
#	define ZERO_TAG(name, tag, ...) FIELD(name, tag, ZeroTag, __VA_ARGS__)
#endif

#ifndef SIMPLE_LIST
#	define SIMPLE_LIST(name, tag, ...) FIELD(name, tag, SimpleList, __VA_ARGS__)
#endif

JCE_STRUCT_DEFAULT_ALIAS(JceTest)
	INT(TestInt, 0)
	FLOAT(TestFloat, 1, IS_OPTIONAL(1.0f))
	MAP(TestMap, 2, TEMPLATE_ARGUMENT(std::int32_t, float))
	LIST(TestList, 3, TEMPLATE_ARGUMENT(double), IS_OPTIONAL((FieldType{ 1.0, 2.0, 3.0 })))
END_JCE_STRUCT(JceTest)

JCE_STRUCT(SignatureReq, "KQQConfig.SignatureReq")
	LONG(uin, 0)
END_JCE_STRUCT(SignatureReq)

JCE_STRUCT_DEFAULT_ALIAS(RequestPacket)
	SHORT(iVersion, 1)
	BYTE(cPacketType, 2, DEFAULT_INITIALIZER(2))
	INT(iMessageType, 3)
	INT(iRequestId, 4)
	STRING1(sServantName, 5)
	STRING1(sFuncName, 6)
	SIMPLE_LIST(sBuffer, 7)
	INT(iTimeout, 8)
	MAP(context, 9, TEMPLATE_ARGUMENT(UsingString, UsingString))
	MAP(status, 10, TEMPLATE_ARGUMENT(UsingString, UsingString))
END_JCE_STRUCT(RequestPacket)

JCE_STRUCT_DEFAULT_ALIAS(RequestHeader)
	INT(a, 0)
	INT(b, 1)
	INT(MsfSeq, 2)
	INT(d, 3)
	STRING1(Uin, 4)
	INT(AppId, 5)
	STRING1(AppIdStr, 6)
	STRING1(h, 7)
	INT(i, 8)
END_JCE_STRUCT(RequestHeader)

JCE_STRUCT_DEFAULT_ALIAS(SDKConfReq)
	INT(UnknownInt, 0)
	INT(iGetSdkLastTime, 1)
	LIST(Uins, 2, TEMPLATE_ARGUMENT(UsingString))
	INT(iGetEspLastTime, 3)
	INT(iGetAppidTime, 4)
END_JCE_STRUCT(SDKConfReq)

#undef SIMPLE_LIST
#undef ZERO_TAG
#undef STRUCT
#undef STRUCT_END
#undef STRUCT_BEGIN
#undef LIST
#undef MAP
#undef STRING4
#undef STRING1
#undef DOUBLE
#undef FLOAT
#undef LONG
#undef INT
#undef SHORT
#undef BYTE
#undef FIELD

#undef TEMPLATE_ARGUMENT
#undef IS_OPTIONAL
#undef DEFAULT_INITIALIZER
#undef NO_OP
#undef ATTRIBUTE_SET

#undef END_JCE_STRUCT
#undef JCE_STRUCT_DEFAULT_ALIAS
#undef JCE_STRUCT
