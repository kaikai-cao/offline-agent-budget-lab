using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

public sealed class E47TpmCommandResult
{
    public uint TbsReturn { get; set; }
    public uint TpmResponseCode { get; set; }
    public byte[] Response { get; set; }
}

public sealed class E47NvPublic
{
    public uint NvIndex { get; set; }
    public ushort NameAlg { get; set; }
    public uint Attributes { get; set; }
    public byte[] AuthPolicy { get; set; }
    public ushort DataSize { get; set; }
    public byte[] Name { get; set; }
    public string NameHex { get { return E47TpmNative.ToHex(Name); } }
}

public static class E47TpmNative
{
    private const uint TPM_VERSION_20 = 2;
    private const uint TBS_INCLUDE_TPM20 = 4;
    private const uint TBS_LOCALITY_ZERO = 0;
    private const uint TBS_PRIORITY_NORMAL = 200;
    private const uint TPM_RS_PW = 0x40000009;
    private const uint TPM_RH_OWNER = 0x40000001;

    private const ushort TPM_ST_NO_SESSIONS = 0x8001;
    private const ushort TPM_ST_SESSIONS = 0x8002;

    private const uint TPM_CC_GET_CAPABILITY = 0x0000017A;
    private const uint TPM_CC_NV_DEFINE_SPACE = 0x0000012A;
    private const uint TPM_CC_NV_UNDEFINE_SPACE = 0x00000122;
    private const uint TPM_CC_NV_READ_PUBLIC = 0x00000169;
    private const uint TPM_CC_NV_INCREMENT = 0x00000134;
    private const uint TPM_CC_NV_READ = 0x0000014E;

    private const uint TPM_CAP_HANDLES = 0x00000001;
    private const uint TPM_CAP_COMMANDS = 0x00000002;
    private const uint TPM_CAP_TPM_PROPERTIES = 0x00000006;
    private const uint TPM_PT_PERMANENT = 0x00000200;
    private const uint TPM_PT_STARTUP_CLEAR = 0x00000201;

    private const uint OWNER_NV_HANDLE = 0x01BFFFFE;
    private const uint NV_ATTRIBUTES = 0x00040014; // TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE | TPM_NT_COUNTER
    private const ushort NAME_ALG_SHA256 = 0x000B;

    [StructLayout(LayoutKind.Sequential)]
    private struct TBS_CONTEXT_PARAMS2
    {
        public uint version;
        public uint flags;
    }

    [DllImport("tbs.dll", ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
    private static extern uint Tbsi_Context_Create(ref TBS_CONTEXT_PARAMS2 parameters, out IntPtr context);

    [DllImport("tbs.dll", ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
    private static extern uint Tbsip_Context_Close(IntPtr context);

    [DllImport("tbs.dll", ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
    private static extern uint Tbsip_Submit_Command(
        IntPtr context,
        uint locality,
        uint priority,
        [In] byte[] command,
        uint commandSize,
        [Out] byte[] result,
        ref uint resultSize);

    public static IntPtr OpenContext()
    {
        TBS_CONTEXT_PARAMS2 p = new TBS_CONTEXT_PARAMS2();
        p.version = TPM_VERSION_20;
        p.flags = TBS_INCLUDE_TPM20;
        IntPtr ctx;
        uint rc = Tbsi_Context_Create(ref p, out ctx);
        if (rc != 0) throw new InvalidOperationException("Tbsi_Context_Create failed: 0x" + rc.ToString("X8"));
        return ctx;
    }

    public static uint CloseContext(IntPtr context)
    {
        if (context == IntPtr.Zero) return 0;
        return Tbsip_Context_Close(context);
    }

    private static E47TpmCommandResult Submit(IntPtr context, byte[] command)
    {
        try
        {
            byte[] response = new byte[8192];
            uint responseSize = (uint)response.Length;
            uint tbs = Tbsip_Submit_Command(context, TBS_LOCALITY_ZERO, TBS_PRIORITY_NORMAL,
                command, (uint)command.Length, response, ref responseSize);
            if (tbs != 0)
            {
                return new E47TpmCommandResult { TbsReturn = tbs, TpmResponseCode = UInt32.MaxValue, Response = null };
            }
            if (responseSize < 10 || responseSize > response.Length)
                throw new InvalidOperationException("TBS returned an invalid TPM response size: " + responseSize);
            byte[] exact = new byte[(int)responseSize];
            Buffer.BlockCopy(response, 0, exact, 0, (int)responseSize);
            uint reported = ReadBE32(exact, 2);
            if (reported != responseSize)
                throw new InvalidOperationException("TPM responseSize field does not match returned buffer length.");
            return new E47TpmCommandResult
            {
                TbsReturn = 0,
                TpmResponseCode = ReadBE32(exact, 6),
                Response = exact
            };
        }
        finally
        {
            // The command contains the NV authValue. Reduce its lifetime in managed memory.
            if (command != null) Array.Clear(command, 0, command.Length);
        }
    }

    private static byte[] BuildPasswordAuthorization(byte[] authValue)
    {
        if (authValue == null) authValue = new byte[0];
        if (authValue.Length > 64) throw new ArgumentException("TPM authValue exceeds 64 bytes.");
        List<byte> a = new List<byte>();
        AddBE32(a, TPM_RS_PW);  // TPM_RS_PW
        AddBE16(a, 0);          // empty nonce
        a.Add(0);               // sessionAttributes
        AddBE16(a, (ushort)authValue.Length);
        a.AddRange(authValue);
        return a.ToArray();
    }

    private static byte[] BuildSessionsCommand(uint commandCode, uint[] handles, byte[] sessionAuth, byte[] parameters)
    {
        List<byte> body = new List<byte>();
        foreach (uint h in handles) AddBE32(body, h);
        AddBE32(body, (uint)sessionAuth.Length);
        body.AddRange(sessionAuth);
        if (parameters != null) body.AddRange(parameters);
        List<byte> command = new List<byte>();
        AddBE16(command, TPM_ST_SESSIONS);
        AddBE32(command, (uint)(10 + body.Count));
        AddBE32(command, commandCode);
        command.AddRange(body);
        return command.ToArray();
    }

    private static byte[] BuildNoSessionsCommand(uint commandCode, uint[] handles, byte[] parameters)
    {
        List<byte> body = new List<byte>();
        foreach (uint h in handles) AddBE32(body, h);
        if (parameters != null) body.AddRange(parameters);
        List<byte> command = new List<byte>();
        AddBE16(command, TPM_ST_NO_SESSIONS);
        AddBE32(command, (uint)(10 + body.Count));
        AddBE32(command, commandCode);
        command.AddRange(body);
        return command.ToArray();
    }

    public static E47TpmCommandResult GetCapability(IntPtr context, uint capability, uint property, uint propertyCount)
    {
        List<byte> p = new List<byte>();
        AddBE32(p, capability);
        AddBE32(p, property);
        AddBE32(p, propertyCount);
        return Submit(context, BuildNoSessionsCommand(TPM_CC_GET_CAPABILITY, new uint[0], p.ToArray()));
    }

    public static E47TpmCommandResult NvReadPublic(IntPtr context, uint handle)
    {
        return Submit(context, BuildNoSessionsCommand(TPM_CC_NV_READ_PUBLIC, new uint[] { handle }, new byte[0]));
    }

    private static byte[] BuildNvDefineCounterCommand(uint handle, byte[] nvAuth)
    {
        if (nvAuth == null || nvAuth.Length != 32)
            throw new ArgumentException("The experiment requires a 32-byte SHA-256 NV authValue.");
        List<byte> parameters = new List<byte>();
        AddBE16(parameters, (ushort)nvAuth.Length);
        parameters.AddRange(nvAuth);                 // TPM2B_AUTH auth
        List<byte> publicBody = new List<byte>();
        AddBE32(publicBody, handle);                 // nvIndex
        AddBE16(publicBody, NAME_ALG_SHA256);        // nameAlg
        AddBE32(publicBody, NV_ATTRIBUTES);          // AUTHREAD | AUTHWRITE | COUNTER; ORDERLY CLEAR
        AddBE16(publicBody, 0);                      // empty authPolicy
        AddBE16(publicBody, 8);                      // Counter dataSize
        AddBE16(parameters, (ushort)publicBody.Count); // TPM2B_NV_PUBLIC size
        parameters.AddRange(publicBody);
        return BuildSessionsCommand(TPM_CC_NV_DEFINE_SPACE, new uint[] { TPM_RH_OWNER },
            BuildPasswordAuthorization(new byte[0]), parameters.ToArray());
    }

    private static byte[] BuildNvIncrementCommand(uint handle, byte[] nvAuth)
    {
        return BuildSessionsCommand(TPM_CC_NV_INCREMENT, new uint[] { handle, handle },
            BuildPasswordAuthorization(nvAuth), new byte[0]);
    }

    private static byte[] BuildNvReadCounterCommand(uint handle, byte[] nvAuth)
    {
        List<byte> parameters = new List<byte>();
        AddBE16(parameters, 8); // size
        AddBE16(parameters, 0); // offset; recommended for Counter interoperability
        return BuildSessionsCommand(TPM_CC_NV_READ, new uint[] { handle, handle },
            BuildPasswordAuthorization(nvAuth), parameters.ToArray());
    }

    private static byte[] BuildNvUndefineOwnerCommand(uint handle)
    {
        return BuildSessionsCommand(TPM_CC_NV_UNDEFINE_SPACE, new uint[] { TPM_RH_OWNER, handle },
            BuildPasswordAuthorization(new byte[0]), new byte[0]);
    }

    public static E47TpmCommandResult NvDefineCounter(IntPtr context, uint handle, byte[] nvAuth)
    {
        return Submit(context, BuildNvDefineCounterCommand(handle, nvAuth));
    }

    public static E47TpmCommandResult NvIncrement(IntPtr context, uint handle, byte[] nvAuth)
    {
        return Submit(context, BuildNvIncrementCommand(handle, nvAuth));
    }

    public static E47TpmCommandResult NvReadCounter(IntPtr context, uint handle, byte[] nvAuth)
    {
        return Submit(context, BuildNvReadCounterCommand(handle, nvAuth));
    }

    public static E47TpmCommandResult NvUndefineOwner(IntPtr context, uint handle)
    {
        return Submit(context, BuildNvUndefineOwnerCommand(handle));
    }

    public static string[] RunOfflineMarshallingSelfTests()
    {
        byte[] auth = new byte[32];
        for (int i = 0; i < auth.Length; i++) auth[i] = (byte)i;
        byte[][] commands = new byte[][] {
            BuildNvDefineCounterCommand(OWNER_NV_HANDLE, auth),
            BuildNvIncrementCommand(OWNER_NV_HANDLE, auth),
            BuildNvReadCounterCommand(OWNER_NV_HANDLE, auth),
            BuildNvUndefineOwnerCommand(OWNER_NV_HANDLE),
            BuildNoSessionsCommand(TPM_CC_GET_CAPABILITY, new uint[0], new byte[12]),
            BuildNoSessionsCommand(TPM_CC_NV_READ_PUBLIC, new uint[] { OWNER_NV_HANDLE }, new byte[0])
        };
        int[] expectedLengths = new int[] { 77, 63, 67, 31, 22, 14 };
        uint[] expectedCodes = new uint[] { TPM_CC_NV_DEFINE_SPACE, TPM_CC_NV_INCREMENT, TPM_CC_NV_READ,
            TPM_CC_NV_UNDEFINE_SPACE, TPM_CC_GET_CAPABILITY, TPM_CC_NV_READ_PUBLIC };
        ushort[] expectedTags = new ushort[] { TPM_ST_SESSIONS, TPM_ST_SESSIONS, TPM_ST_SESSIONS,
            TPM_ST_SESSIONS, TPM_ST_NO_SESSIONS, TPM_ST_NO_SESSIONS };
        string[] names = new string[] { "NV_DefineSpace", "NV_Increment", "NV_Read", "NV_UndefineSpace", "GetCapability", "NV_ReadPublic" };
        List<string> passed = new List<string>();
        for (int i = 0; i < commands.Length; i++)
        {
            byte[] c = commands[i];
            if (c.Length != expectedLengths[i] || ReadBE32(c, 2) != (uint)c.Length ||
                ReadBE32(c, 6) != expectedCodes[i] || ReadBE16(c, 0) != expectedTags[i])
                throw new InvalidOperationException("Offline TPM command marshalling self-test failed for " + names[i]);
            passed.Add(names[i] + ": PASS (" + c.Length + " bytes)");
        }
        if (ReadBE32(commands[0], 10) != TPM_RH_OWNER || ReadBE32(commands[1], 10) != OWNER_NV_HANDLE ||
            ReadBE32(commands[1], 14) != OWNER_NV_HANDLE || ReadBE32(commands[2], 10) != OWNER_NV_HANDLE ||
            ReadBE32(commands[2], 14) != OWNER_NV_HANDLE || ReadBE32(commands[3], 10) != TPM_RH_OWNER ||
            ReadBE32(commands[3], 14) != OWNER_NV_HANDLE)
            throw new InvalidOperationException("Offline TPM command handle-order self-test failed.");
        if (ReadBE16(commands[0], 61) != 14 || ReadBE32(commands[0], 63) != OWNER_NV_HANDLE ||
            ReadBE16(commands[0], 67) != NAME_ALG_SHA256 || ReadBE32(commands[0], 69) != NV_ATTRIBUTES ||
            ReadBE16(commands[0], 73) != 0 || ReadBE16(commands[0], 75) != 8)
            throw new InvalidOperationException("Offline NV_DefineSpace public-area marshalling test failed.");
        if (ReadBE16(commands[2], 63) != 8 || ReadBE16(commands[2], 65) != 0)
            throw new InvalidOperationException("Offline NV_Read size/offset marshalling test failed.");
        passed.Add("Handle ordering and command parameter fields: PASS");

        string clearName = ComputeExpectedCounterName(OWNER_NV_HANDLE, false);
        string writtenName = ComputeExpectedCounterName(OWNER_NV_HANDLE, true);
        if (clearName != "000b8da67e5ccf4b8541929bea0f0919de2870f54abcb905cdca6d10001f55c173aa" ||
            writtenName != "000b667669216ae5f67a6da327553d35f90fbb553944969f5f28921a71532b37b201" || clearName == writtenName)
            throw new InvalidOperationException("Offline NV Name calculation test failed: TPMA_NV_WRITTEN must change the Name.");
        passed.Add("NV Name calculation and dynamic WRITTEN-bit handling: PASS");

        byte[] syntheticReadPublic = BuildSyntheticNvReadPublicResponse(OWNER_NV_HANDLE, false);
        E47NvPublic parsedClear = ParseNvReadPublic(new E47TpmCommandResult { TbsReturn = 0, TpmResponseCode = 0, Response = syntheticReadPublic });
        if (parsedClear.Attributes != NV_ATTRIBUTES || parsedClear.NameHex != clearName || parsedClear.DataSize != 8)
            throw new InvalidOperationException("Offline NV_ReadPublic parser test failed for WRITTEN=CLEAR.");
        byte[] syntheticWrittenPublic = BuildSyntheticNvReadPublicResponse(OWNER_NV_HANDLE, true);
        E47NvPublic parsedWritten = ParseNvReadPublic(new E47TpmCommandResult { TbsReturn = 0, TpmResponseCode = 0, Response = syntheticWrittenPublic });
        if (parsedWritten.Attributes != (NV_ATTRIBUTES | 0x20000000u) || parsedWritten.NameHex != writtenName || parsedWritten.DataSize != 8)
            throw new InvalidOperationException("Offline NV_ReadPublic parser test failed for WRITTEN=SET.");
        passed.Add("NV_ReadPublic response parsing (both WRITTEN states): PASS");

        byte[] syntheticCounterRead = BuildSyntheticNvReadCounterResponse(0x0102030405060708UL);
        ulong parsedCounter = ParseNvReadCounter(new E47TpmCommandResult { TbsReturn = 0, TpmResponseCode = 0, Response = syntheticCounterRead });
        if (parsedCounter != 0x0102030405060708UL)
            throw new InvalidOperationException("Offline NV_Read counter response parser test failed.");
        passed.Add("NV_Read counter value parsing: PASS");

        // TPM_CAP_COMMANDS returns TPMA_CC entries. The low 16 bits are commandIndex;
        // upper attribute bits must not cause an advertised command to be missed.
        byte[] syntheticCommands = BuildSyntheticCapabilityCommandsResponse(
            0x00000134u | 0x00010000u, false);
        bool commandsMore;
        uint[] parsedCommands = ParseCapabilityCommands(
            new E47TpmCommandResult { TbsReturn = 0, TpmResponseCode = 0, Response = syntheticCommands },
            out commandsMore);
        if (commandsMore || parsedCommands.Length != 1 ||
            (parsedCommands[0] & 0x0000FFFFu) != 0x00000134u)
            throw new InvalidOperationException("Offline TPM_CAP_COMMANDS parser test failed.");
        passed.Add("TPM_CAP_COMMANDS / TPMA_CC parser (commandIndex mask): PASS");

        return passed.ToArray();
    }


    private static byte[] BuildSyntheticCapabilityCommandsResponse(uint commandAttributes, bool moreData)
    {
        List<byte> response = new List<byte>();
        AddBE16(response, TPM_ST_NO_SESSIONS);
        AddBE32(response, 23); // 10-byte header + 1 + 4 + 4 + one TPMA_CC
        AddBE32(response, 0);
        response.Add(moreData ? (byte)1 : (byte)0);
        AddBE32(response, TPM_CAP_COMMANDS);
        AddBE32(response, 1);
        AddBE32(response, commandAttributes);
        return response.ToArray();
    }

    private static byte[] BuildSyntheticNvReadPublicResponse(uint handle, bool written)
    {
        List<byte> publicBody = new List<byte>();
        AddBE32(publicBody, handle);
        AddBE16(publicBody, NAME_ALG_SHA256);
        AddBE32(publicBody, NV_ATTRIBUTES | (written ? 0x20000000u : 0u));
        AddBE16(publicBody, 0);
        AddBE16(publicBody, 8);
        byte[] nameBytes = HexToBytes(ComputeExpectedCounterName(handle, written));
        List<byte> response = new List<byte>();
        AddBE16(response, TPM_ST_NO_SESSIONS);
        AddBE32(response, (uint)(10 + 2 + publicBody.Count + 2 + nameBytes.Length));
        AddBE32(response, 0);
        AddBE16(response, (ushort)publicBody.Count);
        response.AddRange(publicBody);
        AddBE16(response, (ushort)nameBytes.Length);
        response.AddRange(nameBytes);
        return response.ToArray();
    }

    private static byte[] BuildSyntheticNvReadCounterResponse(ulong value)
    {
        List<byte> response = new List<byte>();
        AddBE16(response, TPM_ST_SESSIONS);
        AddBE32(response, 29);
        AddBE32(response, 0);
        AddBE32(response, 10); // parameterSize: TPM2B_MAX_NV_BUFFER (2 + 8)
        AddBE16(response, 8);
        for (int i = 7; i >= 0; i--) response.Add((byte)(value >> (i * 8)));
        AddBE16(response, 0); // password-session response nonce
        response.Add(0x01);   // Password response: continueSession is always SET
        AddBE16(response, 0);  // response HMAC
        return response.ToArray();
    }

    private static byte[] HexToBytes(string hex)
    {
        if (hex == null || (hex.Length % 2) != 0) throw new ArgumentException("Invalid hex string.");
        byte[] result = new byte[hex.Length / 2];
        for (int i = 0; i < result.Length; i++) result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return result;
    }

    public static uint GetResponseCode(E47TpmCommandResult r)
    {
        if (r == null) throw new ArgumentNullException("r");
        if (r.TbsReturn != 0) throw new InvalidOperationException("TBS return: 0x" + r.TbsReturn.ToString("X8"));
        return r.TpmResponseCode;
    }

    public static uint[] ParseCapabilityHandles(E47TpmCommandResult r, out bool moreData)
    {
        RequireSuccess(r, "TPM2_GetCapability(TPM_CAP_HANDLES)");
        byte[] b = r.Response;
        if (ReadBE16(b, 0) != TPM_ST_NO_SESSIONS || b.Length < 19 || ReadBE32(b, 11) != TPM_CAP_HANDLES)
            throw new InvalidOperationException("Unexpected TPM_CAP_HANDLES response layout.");
        moreData = b[10] != 0;
        uint count = ReadBE32(b, 15);
        if (count > 128 || b.Length != 19 + (int)count * 4)
            throw new InvalidOperationException("Invalid TPM_CAP_HANDLES count or response length.");
        uint[] items = new uint[(int)count];
        for (int i = 0; i < count; i++) items[i] = ReadBE32(b, 19 + i * 4);
        return items;
    }


    public static uint[] ParseCapabilityCommands(E47TpmCommandResult r, out bool moreData)
    {
        RequireSuccess(r, "TPM2_GetCapability(TPM_CAP_COMMANDS)");
        byte[] b = r.Response;
        if (ReadBE16(b, 0) != TPM_ST_NO_SESSIONS || b.Length < 19 || ReadBE32(b, 11) != TPM_CAP_COMMANDS)
            throw new InvalidOperationException("Unexpected TPM_CAP_COMMANDS response layout.");
        moreData = b[10] != 0;
        uint count = ReadBE32(b, 15);
        if (count > 128 || b.Length != 19 + (int)count * 4)
            throw new InvalidOperationException("Invalid TPM_CAP_COMMANDS count or response length.");
        uint[] items = new uint[(int)count];
        for (int i = 0; i < count; i++) items[i] = ReadBE32(b, 19 + i * 4);
        return items;
    }

    public static uint ParseSingleTaggedProperty(E47TpmCommandResult r, uint expectedProperty, out bool moreData)
    {
        RequireSuccess(r, "TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)");
        byte[] b = r.Response;
        if (ReadBE16(b, 0) != TPM_ST_NO_SESSIONS || b.Length < 27 || ReadBE32(b, 11) != TPM_CAP_TPM_PROPERTIES)
            throw new InvalidOperationException("Unexpected TPM_CAP_TPM_PROPERTIES response layout.");
        moreData = b[10] != 0;
        uint count = ReadBE32(b, 15);
        if (count != 1 || b.Length != 27)
            throw new InvalidOperationException("Expected exactly one tagged TPM property.");
        uint returnedProperty = ReadBE32(b, 19);
        if (returnedProperty != expectedProperty)
            throw new InvalidOperationException("TPM returned a different property identifier.");
        return ReadBE32(b, 23);
    }

    public static E47NvPublic ParseNvReadPublic(E47TpmCommandResult r)
    {
        RequireSuccess(r, "TPM2_NV_ReadPublic");
        byte[] b = r.Response;
        if (ReadBE16(b, 0) != TPM_ST_NO_SESSIONS || b.Length < 14)
            throw new InvalidOperationException("Unexpected NV_ReadPublic response tag or size.");
        int publicSize = ReadBE16(b, 10);
        int publicStart = 12;
        int publicEnd = publicStart + publicSize;
        if (publicSize < 14 || publicEnd + 2 > b.Length)
            throw new InvalidOperationException("Invalid TPM2B_NV_PUBLIC size.");
        byte[] publicBody = new byte[publicSize];
        Buffer.BlockCopy(b, publicStart, publicBody, 0, publicSize);
        uint index = ReadBE32(publicBody, 0);
        ushort nameAlg = ReadBE16(publicBody, 4);
        uint attrs = ReadBE32(publicBody, 6);
        int policySize = ReadBE16(publicBody, 10);
        if (12 + policySize + 2 != publicBody.Length)
            throw new InvalidOperationException("Invalid TPMS_NV_PUBLIC authPolicy/dataSize layout.");
        byte[] policy = new byte[policySize];
        if (policySize > 0) Buffer.BlockCopy(publicBody, 12, policy, 0, policySize);
        ushort dataSize = ReadBE16(publicBody, 12 + policySize);
        int nameSize = ReadBE16(b, publicEnd);
        int nameStart = publicEnd + 2;
        if (nameStart + nameSize != b.Length)
            throw new InvalidOperationException("Invalid TPM2B_NAME length.");
        byte[] name = new byte[nameSize];
        Buffer.BlockCopy(b, nameStart, name, 0, nameSize);
        return new E47NvPublic { NvIndex = index, NameAlg = nameAlg, Attributes = attrs, AuthPolicy = policy, DataSize = dataSize, Name = name };
    }

    public static string ComputeExpectedCounterName(uint handle, bool written)
    {
        List<byte> pub = new List<byte>();
        AddBE32(pub, handle);
        AddBE16(pub, NAME_ALG_SHA256);
        uint attributes = NV_ATTRIBUTES | (written ? 0x20000000u : 0u); // TPMA_NV_WRITTEN changes the NV Name.
        AddBE32(pub, attributes);
        AddBE16(pub, 0); // empty authPolicy
        AddBE16(pub, 8);
        byte[] digest;
        using (SHA256 sha = SHA256.Create()) digest = sha.ComputeHash(pub.ToArray());
        List<byte> name = new List<byte>();
        AddBE16(name, NAME_ALG_SHA256);
        name.AddRange(digest);
        return ToHex(name.ToArray());
    }

    public static ulong ParseNvReadCounter(E47TpmCommandResult r)
    {
        RequireSuccess(r, "TPM2_NV_Read(counter)");
        byte[] b = r.Response;
        if (ReadBE16(b, 0) != TPM_ST_SESSIONS || b.Length < 29)
            throw new InvalidOperationException("Unexpected NV_Read response tag or size.");
        uint parameterSize = ReadBE32(b, 10);
        if (parameterSize != 10) throw new InvalidOperationException("Expected a 10-byte TPM2B counter parameter.");
        ushort dataSize = ReadBE16(b, 14);
        if (dataSize != 8) throw new InvalidOperationException("TPM counter data size is not eight bytes.");
        ulong value = 0;
        for (int i = 0; i < 8; i++) value = (value << 8) | b[16 + i];
        int authStart = 14 + (int)parameterSize;
        int nonceSize = ReadBE16(b, authStart);
        int p = authStart + 2 + nonceSize;
        if (nonceSize != 0 || p + 3 > b.Length) throw new InvalidOperationException("Unexpected password-session nonce in response.");
        byte attrs = b[p++];
        int hmacSize = ReadBE16(b, p); p += 2;
        if (attrs != 0x01 || hmacSize != 0 || p + hmacSize != b.Length)
        {
            throw new InvalidOperationException(
                $"Unexpected password-session response authorization: " +
                $"attrs=0x{attrs:X2}, hmacSize={hmacSize}, " +
                $"authEnd={p + hmacSize}, responseLength={b.Length}.");
        }
        return value;
    }

    public static void RequireSuccess(E47TpmCommandResult r, string operation)
    {
        if (r == null) throw new ArgumentNullException("r");
        if (r.TbsReturn != 0) throw new InvalidOperationException(operation + " TBS return: 0x" + r.TbsReturn.ToString("X8"));
        if (r.Response == null || r.Response.Length < 10)
            throw new InvalidOperationException(operation + " did not return a valid TPM response.");
        if (r.TpmResponseCode != 0)
            throw new InvalidOperationException(operation + " TPM response: 0x" + r.TpmResponseCode.ToString("X8"));
    }

    public static ushort ReadBE16(byte[] b, int o)
    {
        if (b == null || o < 0 || o + 2 > b.Length) throw new ArgumentOutOfRangeException("o");
        return (ushort)((b[o] << 8) | b[o + 1]);
    }
    public static uint ReadBE32(byte[] b, int o)
    {
        if (b == null || o < 0 || o + 4 > b.Length) throw new ArgumentOutOfRangeException("o");
        return ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3];
    }
    private static void AddBE16(List<byte> b, ushort v) { b.Add((byte)(v >> 8)); b.Add((byte)v); }
    private static void AddBE32(List<byte> b, uint v) { b.Add((byte)(v >> 24)); b.Add((byte)(v >> 16)); b.Add((byte)(v >> 8)); b.Add((byte)v); }
    public static string ToHex(byte[] b) { return BitConverter.ToString(b ?? new byte[0]).Replace("-", "").ToLowerInvariant(); }
}

