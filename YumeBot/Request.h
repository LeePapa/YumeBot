#pragma once

#include "Tlv.h"

namespace YumeBot::Request
{
	template <std::ptrdiff_t Extent>
	void GenerateRandomBytes(gsl::span<std::byte, Extent> dest)
	{
		std::random_device rd;
		std::default_random_engine engine{ rd() };
		std::uniform_int_distribution<> dist{ 0, std::numeric_limits<std::uint8_t>::max() };
		std::generate_n(dest.data(), dest.size(), [&] { return static_cast<std::byte>(dist(engine)); });
	}

	struct KeyStorage
	{
		std::byte PubKey[25];
		std::byte ShareKey[16];
		std::byte RandomKey[16];

		struct RandomizeTag
		{
		};

		static constexpr RandomizeTag Randomize{};

		KeyStorage(gsl::span<std::byte, 25> const& pubKey, gsl::span<std::byte, 16> const& shareKey,
		           gsl::span<std::byte, 16> const& randomKey)
		{
			std::memcpy(PubKey, pubKey.data(), 25);
			std::memcpy(ShareKey, shareKey.data(), 16);
			std::memcpy(RandomKey, randomKey.data(), 16);
		}

		explicit KeyStorage(RandomizeTag)
		{
			Cryptography::Ecdh::GenerateKeyPair(gsl::make_span(PubKey), gsl::make_span(ShareKey));
			GenerateRandomBytes(gsl::make_span(RandomKey));
		}
	};

	class StringMd5Container
	{
	public:
		StringMd5Container(UsingString value) : m_Value{ std::move(value) }
		{
			Cryptography::Md5::Calculate(gsl::as_bytes(m_Value.GetView().GetTrimmedSpan()), m_Md5);
		}

		UsingString const& GetValue() const noexcept
		{
			return m_Value;
		}

		gsl::span<const std::byte, 16> GetMd5() const noexcept
		{
			return m_Md5;
		}

	private:
		UsingString m_Value;
		std::array<std::byte, 16> m_Md5;
	};

	struct RequestContext
	{
		std::uint32_t Uin;
		std::array<std::byte, 16> PasswordMd5;

		StringMd5Container Imei;
		StringMd5Container WifiMac;
		StringMd5Container AndroidId;

		std::uint32_t ServerTime = Utility::GetPosixTime();
		LocaleIdEnum CurrentLocaleId = LocaleIdEnum::ZH_CN;

		UsingString OsVersion = DefaultOsVersion;

		KeyStorage Keys{ KeyStorage::Randomize };

		std::uint32_t MSalt{};

		UsingString SimOperatorName;
		ConnectionTypeEnum ConnectionType;
		UsingString Apn;

		UsingString ApkVersion = DefaultApkVersion;
		gsl::span<const std::byte> ApkSignature = gsl::as_bytes(gsl::make_span(Signature));

		SsoVersion UsingSsoVersion = SsoVersion::Version8;

		std::uint32_t AppId = DefaultAppId;
		UsingString ApkId = DefaultApkId;

		IpV4Addr ClientIp;
		std::uint32_t InitTime;

		std::array<std::byte, 16> const& GetGuid() const
		{
			if (m_Guid.has_value())
			{
				return m_Guid.value();
			}

			const auto tmp = Imei.GetValue() + WifiMac.GetValue();
			std::array<std::byte, 16> result;
			Cryptography::Md5::Calculate(gsl::as_bytes(tmp.GetView().GetTrimmedSpan()),
			                             gsl::make_span(result));
			return m_Guid.emplace(result);
		}

		std::size_t AcquireRequestSeq() const noexcept
		{
			return std::exchange(m_RequestSeq, (m_RequestSeq + 1) % 200);
		}

		std::size_t AcquireClientSeq() const noexcept
		{
			return std::exchange(m_ClientSeq, (m_ClientSeq + 1) % 200);
		}

		std::array<std::byte, 16> const& GetTGTGTKey() const
		{
			if (m_TGTGTKey.has_value())
			{
				return m_TGTGTKey.value();
			}

			std::array<std::byte, 32> buffer;
			GenerateRandomBytes(gsl::make_span(buffer).subspan(0, 16));
			std::memcpy(buffer.data() + 16, Imei.GetMd5().data(), 16);

			auto& key = m_TGTGTKey.emplace();
			Cryptography::Md5::Calculate(gsl::make_span(buffer), gsl::make_span(key));
			return key;
		}

		void ResetTGTGTKey() const
		{
			m_TGTGTKey.reset();
		}

	private:
		mutable std::optional<std::array<std::byte, 16>> m_Guid;
		mutable std::size_t m_RequestSeq{};
		mutable std::size_t m_ClientSeq{};
		mutable std::optional<std::array<std::byte, 16>> m_TGTGTKey;
	};

	/// @brief  加密类型
	enum class EncryptType
	{
		Ecdh,
		Kc
	};

	template <typename T, std::uint16_t CmdValue, std::uint16_t SubCmdValue,
	          EncryptType EncryptTypeValue>
	struct RequestBase
	{
		static constexpr std::uint16_t Cmd = CmdValue;
		static constexpr std::uint16_t SubCmd = SubCmdValue;
		static constexpr EncryptType UsingEncryptType = EncryptTypeValue;

		void Write(Tlv::TlvBuilder& tlvBuilder, RequestContext const& context, std::size_t seq) const
		{
			static_cast<const T*>(this)->DoWrite(tlvBuilder, context, seq);
		}
	};

	template <typename T, std::uint16_t SubCmdValue>
	struct ResponseBase
	{
		static constexpr std::uint16_t SubCmd = SubCmdValue;

		void ProcessResponse(Cafe::Io::BinaryReader<>& reader, RequestContext& context,
		                     std::size_t seq) const
		{
			return static_cast<const T*>(this)->DoProcessResponse(reader, context, seq);
		}
	};

	class RequestBuilder
	{
	public:
		static constexpr std::size_t RequestHeadSize = 27;

		explicit RequestBuilder(RequestContext context) : m_Context{ std::move(context) }
		{
		}

		/// @return Seq
		template <typename T, std::uint16_t CmdValue, std::uint16_t SubCmdValue,
		          EncryptType EncryptTypeValue>
		std::size_t WriteRequest(Cafe::Io::SeekableStream<Cafe::Io::OutputStream>* stream,
		                         RequestBase<T, CmdValue, SubCmdValue, EncryptTypeValue> const& request)
		{
			const auto seq = m_Context.AcquireRequestSeq();

			Cafe::Io::MemoryStream unencryptedBodyStream;
			Cafe::Io::BinaryWriter<> writer{ &unencryptedBodyStream, std::endian::big };

			writer.Write(SubCmdValue);

			const auto tlvNumPos = unencryptedBodyStream.GetPosition();
			writer.Write(std::uint16_t{});

			const auto tlvNum = [&] {
				Tlv::TlvBuilder tlvBuilder{ &unencryptedBodyStream };
				request.Write(tlvBuilder, m_Context, seq);
				return tlvBuilder.GetTlvCount();
			}();

			unencryptedBodyStream.SeekFromBegin(tlvNumPos);
			writer.Write(tlvNum);

			Cafe::Io::MemoryStream requestContentStream;
			Cafe::Io::BinaryWriter<Cafe::Io::SeekableStream<Cafe::Io::OutputStream>> requestWriter{
				&requestContentStream, std::endian::big
			};

			// 写入 Head
			const auto clientSeq = m_Context.AcquireClientSeq();
			requestWriter.Write(std::uint8_t{ 2 });
			const auto totalSizePos = requestContentStream.GetPosition();
			requestWriter.Write(std::uint16_t{});
			requestWriter.Write(DefaultClientVersion);
			requestWriter.Write(CmdValue);
			requestWriter.Write(seq);
			requestWriter.Write(m_Context.Uin);
			requestWriter.Write(std::uint8_t{ 3 });
			requestWriter.Write(std::uint8_t{ 7 });
			requestWriter.Write(std::uint8_t{});     // retry
			requestWriter.Write(std::uint32_t{ 2 }); // ext type
			requestWriter.Write(std::uint32_t{});    // app client type
			requestWriter.Write(std::uint32_t{});    // ext instance

			// 写入加密的 Body
			const auto bodyBeginPos = requestContentStream.GetPosition();
			EncryptBody<EncryptTypeValue>(&requestContentStream,
			                              unencryptedBodyStream.GetInternalStorage());
			const auto bodyEndPos = requestContentStream.GetPosition();
			const auto bodySize = bodyEndPos - bodyBeginPos;

			requestContentStream.SeekFromBegin(totalSizePos);
			requestWriter.Write(static_cast<std::uint16_t>(RequestHeadSize + 2 + bodySize));

			requestContentStream.SeekFromBegin(bodyEndPos);

			// 写入 End
			requestWriter.Write(std::uint8_t{ 3 });

			EncodeRequest(stream, requestContentStream.GetInternalStorage(), seq);

			return seq;
		}

		template <EncryptType EncryptTypeValue>
		void EncryptBody(Cafe::Io::OutputStream* stream, gsl::span<const std::byte> const& body)
		{
			Cafe::Io::BinaryWriter<> writer{ stream, std::endian::big };

			const auto teaKey = [&] {
				if constexpr (EncryptTypeValue == EncryptType::Ecdh)
				{
					writer.Write(std::uint16_t{ 0x0101 });
					stream->WriteBytes(gsl::make_span(m_Context.Keys.RandomKey));
					writer.Write(std::uint16_t{ 0x0102 });
					writer.Write(static_cast<std::uint16_t>(sizeof m_Context.Keys.PubKey));
					stream->WriteBytes(gsl::make_span(m_Context.Keys.PubKey));

					return Cryptography::Tea::FormatKey(m_Context.Keys.ShareKey);
				}
				else
				{
					writer.Write(std::uint16_t{ 0x0102 });
					stream->WriteBytes(gsl::make_span(m_Context.Keys.RandomKey));
					writer.Write(std::uint16_t{ 0x0102 });
					writer.Write(std::uint16_t{});

					return Cryptography::Tea::FormatKey(m_Context.Keys.RandomKey);
				}
			}();
			Cryptography::Tea::Encrypt(body, stream, teaKey);
		}

		void EncodeRequest(Cafe::Io::SeekableStream<Cafe::Io::OutputStream>* stream,
		                   gsl::span<const std::byte> const& request, std::size_t seq)
		{
			if (m_Context.UsingSsoVersion == SsoVersion::Version8)
			{
				EncodeRequestV8(stream, request, seq);
			}
			else
			{
				assert(m_Context.UsingSsoVersion == SsoVersion::Version9);
				EncodeRequestV9(stream, request, seq);
			}
		}

	private:
		RequestContext m_Context;

		void EncodeRequestV8(Cafe::Io::SeekableStream<Cafe::Io::OutputStream>* stream,
		                     gsl::span<const std::byte> const& request, std::size_t seq)
		{
			constexpr std::uint32_t ssoVersion = static_cast<std::uint32_t>(SsoVersion::Version8);

			Cafe::Io::BinaryWriter<Cafe::Io::SeekableStream<Cafe::Io::OutputStream>> writer{
				stream, std::endian::big
			};

			// 序列化 CSSOReqHead
			const auto lengthPos = stream->GetPosition();
			writer.Write(std::uint32_t{}); // length
			writer.Write(static_cast<std::uint32_t>(seq));
			writer.Write(std::uint32_t{ 100 }); // appId
			writer.Write(m_Context.AppId);      // msfAppId
			writer.Write(static_cast<std::uint8_t>(m_Context.ConnectionType));
			
			std::byte dummy[11]{};
			stream->WriteBytes(gsl::make_span(dummy));  // Unknown array
			
			
		}

		void EncodeRequestV9(Cafe::Io::SeekableStream<Cafe::Io::OutputStream>* stream,
		                     gsl::span<const std::byte> const& request, std::size_t seq)
		{
			// TODO
		}
	};

	struct RequestTGTGT : RequestBase<RequestTGTGT, 2064, 9, EncryptType::Ecdh>
	{
		void DoWrite(Tlv::TlvBuilder& tlvBuilder, RequestContext const& context, std::size_t seq) const
		{
			const auto& guid = context.GetGuid();

			constexpr std::uint32_t rc = 0;
			// 意义不明。。。这个 AppId 不遵守其他地方的约定，总是 16
			constexpr auto appId = 16;
			constexpr auto clientVersion = 1;
			constexpr auto savePwd = false;
			const auto passwordMd5 = context.PasswordMd5;
			const auto tgtgtKey = context.GetTGTGTKey();
			constexpr auto sigSrc = DefualtSigSrc;
			constexpr auto bitmap = DefaultBitmap;
			constexpr auto getSig = DefaultGetSig;
			constexpr auto getSig1 = DefaultGetSig1;
			const auto wxAppId = context.AppId;
			constexpr auto picType = 0;
			constexpr auto capType = 0;
			constexpr auto picSize = 0;
			constexpr auto retType = 1;
			constexpr auto& domains = DefaultDomains;

			tlvBuilder.WriteTlv(Tlv::TlvT<0x18>{ appId, clientVersion, context.Uin, rc });
			tlvBuilder.WriteTlv(Tlv::TlvT<0x1>{ context.Uin, context.InitTime, context.ClientIp });
			tlvBuilder.WriteTlv(Tlv::TlvT<0x106>{
			    appId, context.AppId, clientVersion, context.Uin, context.InitTime, context.ClientIp,
			    savePwd, passwordMd5, context.MSalt, tgtgtKey, false, guid, sigSrc });
			tlvBuilder.WriteTlv(Tlv::TlvT<0x100>{ appId, context.AppId, wxAppId, getSig1 });
			tlvBuilder.WriteTlv(Tlv::TlvT<0x107>{ picType, capType, picSize, retType });
			tlvBuilder.WriteTlv(Tlv::TlvT<0x116>{ bitmap, getSig, {} });
			tlvBuilder.WriteTlv(Tlv::TlvT<0x145>{ guid });
			tlvBuilder.WriteTlv(Tlv::TlvT<0x154>{ static_cast<std::uint32_t>(seq) });
			tlvBuilder.WriteTlv(
			    Tlv::TlvT<0x141>{ context.SimOperatorName, context.ConnectionType, context.Apn });
			tlvBuilder.WriteTlv(Tlv::TlvT<0x8>{ 0, context.CurrentLocaleId, 0 });
			tlvBuilder.WriteTlv(
			    Tlv::TlvT<0x147>{ appId, DefaultApkVersion, gsl::as_bytes(gsl::make_span(Signature)) });
			tlvBuilder.WriteTlv(Tlv::TlvT<0x177>{ BuildTime, SdkVersion });

			if (!Ksid.empty())
			{
				tlvBuilder.WriteTlv(Tlv::TlvT<0x108>{ std::vector<std::byte>(Ksid.begin(), Ksid.end()) });
			}

			if (!context.WifiMac.GetValue().IsEmpty())
			{
				tlvBuilder.WriteTlv(Tlv::TlvT<0x187>{ context.WifiMac.GetMd5() });
			}

			if (!context.AndroidId.GetValue().IsEmpty())
			{
				tlvBuilder.WriteTlv(Tlv::TlvT<0x188>{ context.AndroidId.GetMd5() });
			}

			if (!context.Imei.GetValue().IsEmpty())
			{
				tlvBuilder.WriteTlv(Tlv::TlvT<0x109>{ context.Imei.GetMd5() });
			}

			// TODO
		}

		gsl::span<const std::byte> Ksid;
		gsl::span<const std::byte> SigSession;
	};
} // namespace YumeBot::Request
