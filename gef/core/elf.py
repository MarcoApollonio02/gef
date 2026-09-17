"""GEF ELF parsing and checksec helpers (Layer 1).

Contains `Elf` (basic ELF parsing: header, program/section headers, dynamic
entries and the `checksec` security-property report) and `Checksec` (CET / MTE /
PAC status probing through `call-syscall` and procfs).

Reads of the mutable global `current_arch` go through `runtime.current_arch`
(never a by-name import) to avoid the stale-binding pitfall documented in
runtime.py. References to modules that are not yet extracted (process, auxv,
utils) are imported lazily inside the method that needs them.
"""
import gdb
import os
import struct
import subprocess

from gef.core import runtime
from gef.core.cache import Cache
from gef.core.config import Config
from gef.core.memory import read_int_from_memory, read_memory, u32

class Elf:
    """Basic ELF parsing."""

    # e_ident[EI_MAG0:EI_MAG3]
    ELF_MAGIC                = 0x7f454c46

    # e_ident[EI_CLASS]
    ELF_CLASS_NONE           = 0
    ELF_32_BITS              = 1
    ELF_64_BITS              = 2

    # e_ident[EI_DATA]
    ELF_DATA_NONE            = 0
    LITTLE_ENDIAN            = 1
    BIG_ENDIAN               = 2

    # e_ident[EI_OSABI]
    OSABI_SYSTEMV            = 0 # UNIX System V ABI
    OSABI_HPUX               = 1 # Hewlett-Packard HP-UX
    OSABI_NETBSD             = 2 # NetBSD
    OSABI_LINUX              = 3 # GNU Linux
    OSABI_HURD               = 4 # GNU Hurd
    OSABI_86OPEN             = 5 # 86Open Common IA32 ABI
    OSABI_SOLARIS            = 6 # Sun Solaris
    OSABI_AIX                = 7 # IBM AIX
    OSABI_IRIX               = 8 # SGI Irix
    OSABI_FREEBSD            = 9 # FreeBSD
    OSABI_TRU64              = 10 # Compaq TRU64 UNIX
    OSABI_MODESTO            = 11 # Novell Modesto
    OSABI_OPENBSD            = 12 # OpenBSD
    OSABI_OPENVMS            = 13 # OpenVMS
    OSABI_NSK                = 14 # Hewlett-Packard Non-Stop Kernel
    OSABI_AROS               = 15 # Amiga Research OS
    OSABI_FENIXOS            = 16 # The FenixOS highly scalable multi-core OS
    OSABI_CLOUDABI           = 17 # Nuxi CloudABI
    OSABI_OPENVOS            = 18 # Stratus Technologies OpenVOS
    OSABI_ARM_AEABI          = 64 # ARM EABI
    OSABI_ARM                = 97 # ARM
    OSABI_STANDALONE         = 255 # Standalone (embedded) application

    # e_type
    ET_NONE                  = 0
    ET_REL                   = 1
    ET_EXEC                  = 2
    ET_DYN                   = 3
    ET_CORE                  = 4

    # e_machine
    EM_NONE                  = 0 # No machine
    EM_M32                   = 1 # AT&T WE 32100
    EM_SPARC                 = 2 # SUN SPARC
    EM_386                   = 3 # Intel 80386
    EM_68K                   = 4 # Motorola m68k family
    EM_88K                   = 5 # Motorola m88k family
    EM_IAMCU                 = 6 # Intel MCU
    EM_860                   = 7 # Intel 80860
    EM_MIPS                  = 8 # MIPS R3000 big-endian
    EM_S370                  = 9 # IBM System/370 Processor
    EM_MIPS_RS3_LE           = 10 # MIPS RS3000 Little-endian
    #                          11-14 # Reserved for future use
    EM_PARISC                = 15 # Hewlett-Packard PA-RISC
    #                          16 # Reserved for future use
    EM_VPP500                = 17 # Fujitsu VPP500
    EM_SPARC32PLUS           = 18 # Enhanced instruction set SPARC
    EM_960                   = 19 # Intel 80960
    EM_PPC                   = 20 # PowerPC
    EM_PPC64                 = 21 # 64-bit PowerPC
    EM_S390                  = 22 # IBM System/390 Processor
    EM_SPU                   = 23 # IBM SPU/SPC
    #                          24-35 # Reserved for future use
    EM_V800                  = 36 # NEC V800
    EM_FR20                  = 37 # Fujitsu FR20
    EM_RH32                  = 38 # TRW RH-32
    EM_RCE                   = 39 # Motorola RCE
    EM_ARM                   = 40 # ARM 32-bit architecture (AARCH32)
    EM_ALPHA                 = 41 # Digital Alpha
    EM_SH                    = 42 # Hitachi SH
    EM_SPARCV9               = 43 # SPARC Version 9
    EM_TRICORE               = 44 # Siemens TriCore embedded processor
    EM_ARC                   = 45 # Argonaut RISC Core, Argonaut Technologies Inc.
    EM_H8_300                = 46 # Hitachi H8/300
    EM_H8_300H               = 47 # Hitachi H8/300H
    EM_H8S                   = 48 # Hitachi H8S
    EM_H8_500                = 49 # Hitachi H8/500
    EM_IA_64                 = 50 # Intel IA-64 processor architecture
    EM_MIPS_X                = 51 # Stanford MIPS-X
    EM_COLDFIRE              = 52 # Motorola ColdFire
    EM_68HC12                = 53 # Motorola M68HC12
    EM_MMA                   = 54 # Fujitsu MMA Multimedia Accelerator
    EM_PCP                   = 55 # Siemens PCP
    EM_NCPU                  = 56 # Sony nCPU embedded RISC processor
    EM_NDR1                  = 57 # Denso NDR1 microprocessor
    EM_STARCORE              = 58 # Motorola Star*Core processor
    EM_ME16                  = 59 # Toyota ME16 processor
    EM_ST100                 = 60 # STMicroelectronics ST100 processor
    EM_TINYJ                 = 61 # Advanced Logic Corp. TinyJ embedded processor family
    EM_X86_64                = 62 # AMD x86-64 architecture
    EM_PDSP                  = 63 # Sony DSP Processor
    EM_PDP10                 = 64 # Digital Equipment Corp. PDP-10
    EM_PDP11                 = 65 # Digital Equipment Corp. PDP-11
    EM_FX66                  = 66 # Siemens FX66 microcontroller
    EM_ST9PLUS               = 67 # STMicroelectronics ST9+ 8/16 bit microcontroller
    EM_ST7                   = 68 # STMicroelectronics ST7 8-bit microcontroller
    EM_68HC16                = 69 # Motorola MC68HC16 Microcontroller
    EM_68HC11                = 70 # Motorola MC68HC11 Microcontroller
    EM_68HC08                = 71 # Motorola MC68HC08 Microcontroller
    EM_68HC05                = 72 # Motorola MC68HC05 Microcontroller
    EM_SVX                   = 73 # Silicon Graphics SVx
    EM_ST19                  = 74 # STMicroelectronics ST19 8-bit microcontroller
    EM_VAX                   = 75 # Digital VAX
    EM_CRIS                  = 76 # Axis Communications 32-bit embedded processor
    EM_JAVELIN               = 77 # Infineon Technologies 32-bit embedded processor
    EM_FIREPATH              = 78 # Element 14 64-bit DSP Processor
    EM_ZSP                   = 79 # LSI Logic 16-bit DSP Processor
    EM_MMIX                  = 80 # Donald Knuth's educational 64-bit processor
    EM_HUANY                 = 81 # Harvard University machine-independent object files
    EM_PRISM                 = 82 # SiTera Prism
    EM_AVR                   = 83 # Atmel AVR 8-bit microcontroller
    EM_FR30                  = 84 # Fujitsu FR30
    EM_D10V                  = 85 # Mitsubishi D10V
    EM_D30V                  = 86 # Mitsubishi D30V
    EM_V850                  = 87 # NEC v850
    EM_M32R                  = 88 # Mitsubishi M32R
    EM_MN10300               = 89 # Matsushita MN10300
    EM_MN10200               = 90 # Matsushita MN10200
    EM_PJ                    = 91 # picoJava
    EM_OPENRISC              = 92 # OpenRISC 32-bit embedded processor
    EM_ARC_COMPACT           = 93 # ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)
    EM_XTENSA                = 94 # Tensilica Xtensa Architecture
    EM_VIDEOCORE             = 95 # Alphamosaic VideoCore processor
    EM_TMM_GPP               = 96 # Thompson Multimedia General Purpose Processor
    EM_NS32K                 = 97 # National Semiconductor 32000 series
    EM_TPC                   = 98 # Tenor Network TPC processor
    EM_SNP1K                 = 99 # Trebia SNP 1000 processor
    EM_ST200                 = 100 # STMicroelectronics ST200 microcontroller
    EM_IP2K                  = 101 # Ubicom IP2xxx microcontroller family
    EM_MAX                   = 102 # MAX Processor
    EM_CR                    = 103 # National Semiconductor CompactRISC microprocessor
    EM_F2MC16                = 104 # Fujitsu F2MC16
    EM_MSP430                = 105 # Texas Instruments embedded microcontroller msp430
    EM_BLACKFIN              = 106 # Analog Devices Blackfin (DSP) processor
    EM_SE_C33                = 107 # S1C33 Family of Seiko Epson processors
    EM_SEP                   = 108 # Sharp embedded microprocessor
    EM_ARCA                  = 109 # Arca RISC Microprocessor
    EM_UNICORE               = 110 # Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
    EM_EXCESS                = 111 # eXcess: 16/32/64-bit configurable embedded CPU
    EM_DXP                   = 112 # Icera Semiconductor Inc. Deep Execution Processor
    EM_ALTERA_NIOS2          = 113 # Altera Nios II soft-core processor
    EM_CRX                   = 114 # National Semiconductor CompactRISC CRX microprocessor
    EM_XGATE                 = 115 # Motorola XGATE embedded processor
    EM_C166                  = 116 # Infineon C16x/XC16x processor
    EM_M16C                  = 117 # Renesas M16C series microprocessors
    EM_DSPIC30F              = 118 # Microchip Technology dsPIC30F Digital Signal Controller
    EM_CE                    = 119 # Freescale Communication Engine RISC core
    EM_M32C                  = 120 # Renesas M32C series microprocessors
    #                          121-130 # Reserved for future use
    EM_TSK3000               = 131 # Altium TSK3000 core
    EM_RS08                  = 132 # Freescale RS08 embedded processor
    EM_SHARC                 = 133 # Analog Devices SHARC family of 32-bit DSP processors
    EM_ECOG2                 = 134 # Cyan Technology eCOG2 microprocessor
    EM_SCORE7                = 135 # Sunplus S+core7 RISC processor
    EM_DSP24                 = 136 # New Japan Radio (NJR) 24-bit DSP Processor
    EM_VIDEOCORE3            = 137 # Broadcom VideoCore III processor
    EM_LATTICEMICO32         = 138 # RISC processor for Lattice FPGA architecture
    EM_SE_C17                = 139 # Seiko Epson C17 family
    EM_TI_C6000              = 140 # The Texas Instruments TMS320C6000 DSP family
    EM_TI_C2000              = 141 # The Texas Instruments TMS320C2000 DSP family
    EM_TI_C5500              = 142 # The Texas Instruments TMS320C55x DSP family
    EM_TI_ARP32              = 143 # Texas Instruments Application Specific RISC Processor, 32bit fetch
    EM_TI_PRU                = 144 # Texas Instruments Programmable Realtime Unit
    #                          145-159 # Reserved for future use
    EM_MMDSP_PLUS            = 160 # STMicroelectronics 64bit VLIW Data Signal Processor
    EM_CYPRESS_M8C           = 161 # Cypress M8C microprocessor
    EM_R32C                  = 162 # Renesas R32C series microprocessors
    EM_TRIMEDIA              = 163 # NXP Semiconductors TriMedia architecture family
    EM_QDSP6                 = 164 # QUALCOMM DSP6 Processor
    EM_8051                  = 165 # Intel 8051 and variants
    EM_STXP7X                = 166 # STMicroelectronics STxP7x family of configurable and extensible RISC processors
    EM_NDS32                 = 167 # Andes Technology compact code size embedded RISC processor family
    EM_ECOG1                 = 168 # Cyan Technology eCOG1X family
    EM_ECOG1X                = 168 # Cyan Technology eCOG1X family
    EM_MAXQ30                = 169 # Dallas Semiconductor MAXQ30 Core Micro-controllers
    EM_XIMO16                = 170 # New Japan Radio (NJR) 16-bit DSP Processor
    EM_MANIK                 = 171 # M2000 Reconfigurable RISC Microprocessor
    EM_CRAYNV2               = 172 # Cray Inc. NV2 vector architecture
    EM_RX                    = 173 # Renesas RX family
    EM_METAG                 = 174 # Imagination Technologies META processor architecture
    EM_MCST_ELBRUS           = 175 # MCST Elbrus general purpose hardware architecture
    EM_ECOG16                = 176 # Cyan Technology eCOG16 family
    EM_CR16                  = 177 # National Semiconductor CompactRISC CR16 16-bit microprocessor
    EM_ETPU                  = 178 # Freescale Extended Time Processing Unit
    EM_SLE9X                 = 179 # Infineon Technologies SLE9X core
    EM_L10M                  = 180 # Intel L10M
    EM_K10M                  = 181 # Intel K10M
    #                          182 # Reserved for future Intel use
    EM_AARCH64               = 183 # ARM 64-bit architecture (AARCH64)
    #                          184 # Reserved for future ARM use
    EM_AVR32                 = 185 # Atmel Corporation 32-bit microprocessor family
    EM_STM8                  = 186 # STMicroeletronics STM8 8-bit microcontroller
    EM_TILE64                = 187 # Tilera TILE64 multicore architecture family
    EM_TILEPRO               = 188 # Tilera TILEPro multicore architecture family
    EM_MICROBLAZE            = 189 # Xilinx MicroBlaze 32-bit RISC soft processor core
    EM_CUDA                  = 190 # NVIDIA CUDA architecture
    EM_TILEGX                = 191 # Tilera TILE-Gx multicore architecture family
    EM_CLOUDSHIELD           = 192 # CloudShield architecture family
    EM_COREA_1ST             = 193 # KIPO-KAIST Core-A 1st generation processor family
    EM_COREA_2ND             = 194 # KIPO-KAIST Core-A 2nd generation processor family
    EM_ARCV2                 = 195 # Synopsys ARCompact V2 # codespell:ignore
    EM_OPEN8                 = 196 # Open8 8-bit RISC soft processor core
    EM_RL78                  = 197 # Renesas RL78 family
    EM_VIDEOCORE5            = 198 # Broadcom VideoCore V processor
    EM_78KOR                 = 199 # Renesas 78KOR family
    EM_56800EX               = 200 # Freescale 56800EX Digital Signal Controller (DSC)
    EM_BA1                   = 201 # Beyond BA1 CPU architecture
    EM_BA2                   = 202 # Beyond BA2 CPU architecture
    EM_XCORE                 = 203 # XMOS xCORE processor family
    EM_MCHP_PIC              = 204 # Microchip 8-bit PIC(r) family
    EM_INTELGT               = 205 # Intel Graphics Technology
    EM_INTEL206              = 206 # Reserved by Intel
    EM_INTEL207              = 207 # Reserved by Intel
    EM_INTEL208              = 208 # Reserved by Intel
    EM_INTEL209              = 209 # Reserved by Intel
    EM_KM32                  = 210 # KM211 KM32 32-bit processor
    EM_KMX32                 = 211 # KM211 KMX32 32-bit processor
    EM_KMX16                 = 212 # KM211 KMX16 16-bit processor
    EM_KMX8                  = 213 # KM211 KMX8 8-bit processor
    EM_KVARC                 = 214 # KM211 KVARC processor
    EM_CDP                   = 215 # Paneve CDP architecture family
    EM_COGE                  = 216 # Cognitive Smart Memory Processor
    EM_COOL                  = 217 # Bluechip Systems CoolEngine
    EM_NORC                  = 218 # Nanoradio Optimized RISC
    EM_CSR_KALIMBA           = 219 # CSR Kalimba architecture family
    EM_Z80                   = 220 # Zilog Z80
    EM_VISIUM                = 221 # Controls and Data Services VISIUMcore processor
    EM_FT32                  = 222 # FTDI Chip FT32 high performance 32-bit RISC architecture
    EM_MOXIE                 = 223 # Moxie processor family
    EM_AMDGPU                = 224 # AMD GPU architecture
    #                          225-242 # Reserved
    EM_RISCV                 = 243 # RISC-V
    EM_LANAI                 = 244 # Lanai 32-bit processor
    EM_CEVA                  = 245 # CEVA Processor Architecture Family
    EM_CEVA_X2               = 246 # CEVA X2 Processor Family
    EM_BPF                   = 247 # Linux BPF - in-kernel virtual machine
    EM_GRAPHCORE_IPU         = 248 # Graphcore Intelligent Processing Unit
    EM_IMG1                  = 249 # Imagination Technologies
    EM_NFP                   = 250 # Netronome Flow Processor
    EM_VE                    = 251 # NEC Vector Engine
    EM_CSKY                  = 252 # C-SKY processor family
    EM_ARC_COMPACT3_64       = 253 # Synopsys ARCv2.3 64-bit # codespell:ignore
    EM_MCS6502               = 254 # MOS Technology MCS 6502 processor
    EM_ARC_COMPACT3          = 255 # Synopsys ARCv2.3 32-bit # codespell:ignore
    EM_KVX                   = 256 # Kalray VLIW core of the MPPA processor family
    EM_65816                 = 257 # WDC 65816/65C816
    EM_LOONGARCH             = 258 # LoongArch
    EM_KF32                  = 259 # ChipON KungFu32
    EM_U16_U8CORE            = 260 # LAPIS nX-U16/U8
    EM_TACHYUM               = 261 # Tachyum
    EM_56800EF               = 262 # NXP 56800EF Digital Signal Controller (DSC)

    EM_AVR_UNOFFICIAL        = 0x1057 # AVR (unofficial)
    EM_MSP430_UNOFFICIAL     = 0x1059 # MSP430 (unofficial)
    EM_EPIPHANY_UNOFFICIAL   = 0x1223 # Adapteva Epiphany (unofficial)
    EM_AVR32_UNOFFICIAL      = 0x18ad # Atmel AVR32 (unofficial)
    EM_MT_UNOFFICIAL         = 0x2530 # Morpho MT (unofficial)
    EM_FR30_UNOFFICIAL       = 0x3330 # FR30 (unofficial)
    EM_OPENRISC_OLD          = 0x3426 # OpenRISC (obsolete)
    EM_WEBASSEMBLY           = 0x4157 # Web Assembly binaries (unofficial)
    EM_C166_UNOFFICIAL       = 0x4688 # Infineon C166 (unofficial)
    EM_S12Z                  = 0x4DEF # Freescale S12Z
    EM_FRV_UNOFFICIAL        = 0x5441 # Cygnus FR-V (unofficial)
    EM_DLX_UNOFFICIAL        = 0x5aa5 # DLX (unofficial)
    EM_D10V_UNOFFICIAL       = 0x7650 # Cygnus D10V (unofficial)
    EM_D30V_UNOFFICIAL       = 0x7676 # Cygnus D30V (unofficial)
    EM_IP2K_UNOFFICIAL       = 0x8217 # Ubicom IP2xxx (unofficial)
    EM_OPENRISC_OLD2         = 0x8472 # OpenRISC (obsolete)
    EM_PPC_UNOFFICIAL        = 0x9025 # Cygnus PowerPC (unofficial)
    EM_ALPHA_UNOFFICIAL      = 0x9026 # Digital Alpha (unofficial)
    EM_M32R_UNOFFICIAL       = 0x9041 # Cygnus M32R (unofficial)
    EM_V850_UNOFFICIAL       = 0x9080 # Cygnus V859 (unofficial)
    EM_S390_OLD              = 0xa390 # IBM S/390 (obsolete)
    EM_XTENSA_UNOFFICIAL     = 0xabc7 # Old Xtensa (unofficial)
    EM_XSTORMY_UNOFFICIAL    = 0xad45 # xstormy16 (unofficial)
    EM_MICROBLAZE_UNOFFICIAL = 0xbaab # Old MicroBlaze (unofficial)
    EM_MN10300_UNOFFICIAL    = 0xbeef # Cygnus MN10300 (unofficial)
    EM_MN10200_UNOFFICIAL    = 0xdead # Cygnus MN10200 (unofficial)
    EM_MEP_UNOFFICIAL        = 0xf00d # Toshiba MeP (unofficial)
    EM_M32C_UNOFFICIAL       = 0xfeb0 # Renesas M32C (unofficial)
    EM_IQ2000_UNOFFICIAL     = 0xfeba # Vitesse IQ2000 (unofficial)
    EM_NIOS_UNOFFICIAL       = 0xfebb # NIOS (unofficial)
    EM_MOXIE_UNOFFICIAL      = 0xfeed # Moxie (unofficial)

    # e_version
    EV_NONE                  = 0
    EV_CURRENT               = 1

    # default values
    e_magic                  = ELF_MAGIC
    e_class                  = ELF_64_BITS
    e_endianness             = LITTLE_ENDIAN
    e_eiversion              = None
    e_osabi                  = None
    e_abiversion             = None
    e_pad                    = None # noqa: F841
    e_type                   = ET_EXEC
    e_machine                = EM_X86_64
    e_version                = None
    e_entry                  = 0x00
    e_phoff                  = None
    e_shoff                  = None
    e_flags                  = None
    e_ehsize                 = None
    e_phentsize              = None
    e_phnum                  = None
    e_shentsize              = None
    e_shnum                  = None
    e_shstrndx               = None

    @staticmethod
    @Cache.cache_until_next
    def get_elf(filepath=None):
        """Return an Elf object with caching."""
        try:
            elf = Elf(filepath)
        except Exception:
            elf = None
        return elf

    def __init__(self, elf=None, file_offset=0):
        """Instantiate an ELF object."""
        from gef.core.process import Path
        from gef.core.utils import err

        if elf is None:
            elf = Path.get_filepath()
            if elf is None:
                self.e_magic = None
                err("Could not find the path")
                return

        if isinstance(elf, str):
            if not os.access(elf, os.R_OK):
                err("'{:s}' not found/readable".format(elf))
                self.e_magic = None
                return
            self.fd = open(elf, "rb")
            self.addr = None
            self.seek_init_offset = file_offset
            self.pos = 0
            self.seek(self.pos)
            self.filename = elf
        elif isinstance(elf, int):
            self.fd = None
            self.addr = elf
            self.pos = 0
            self.filename = None
        else:
            raise

        # off 0x0
        self.e_magic, self.e_class, self.e_endianness, self.e_eiversion = struct.unpack(">IBBB", self.read(7))
        # adjust endianness in bin reading
        endian = "<" if self.e_endianness == Elf.LITTLE_ENDIAN else ">"
        # off 0x7
        self.e_osabi, self.e_abiversion = struct.unpack("{}BB".format(endian), self.read(2))
        # off 0x9
        self.e_pad = self.read(7) # noqa
        # off 0x10
        self.e_type, self.e_machine, self.e_version = struct.unpack("{}HHI".format(endian), self.read(8))
        # off 0x18
        if self.e_class == Elf.ELF_64_BITS:
            self.e_entry, self.e_phoff, self.e_shoff = struct.unpack("{}QQQ".format(endian), self.read(24))
        else:
            self.e_entry, self.e_phoff, self.e_shoff = struct.unpack("{}III".format(endian), self.read(12))
        self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum = struct.unpack("{}IHHH".format(endian), self.read(10))
        self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack("{}HHH".format(endian), self.read(6))

        # phdr
        self.phdrs = []
        for i in range(self.e_phnum):
            phdr = Elf.Phdr(self, self.e_phoff + self.e_phentsize * i)
            self.phdrs.append(phdr)

        # shdr
        self.shdrs = []
        for i in range(self.e_shnum):
            try:
                shdr = Elf.Shdr(self, self.e_shoff + self.e_shentsize * i)
                self.shdrs.append(shdr)
            except gdb.MemoryError:
                # Perspective failure. Probably it occurs when parsing ELF loaded into memory.
                # Even if the ELF is loaded, the section header is not loaded. Therefore, it is ignored.
                self.shdrs = []
                break
        else:
            # multiple SHT_NULLs are treated as abnormal
            if sum([x.sh_type == Elf.Shdr.SHT_NULL for x in self.shdrs]) > 1:
                self.shdrs = []

        if self.fd is not None:
            self.fd.close()
            self.fd = None

        # It will be unusable after initialization.
        self.read = None
        self.seek = None
        return

    def __repr__(self):
        if not hasattr(self, "filename"):
            msg = '<{:s}.{:s} object at {:#x}, invalid>'.format(
                self.__module__, self.__class__.__name__, id(self),
            )
        elif self.filename:
            msg = '<{:s}.{:s} object at {:#x}, filename="{:s}">'.format(
                self.__module__, self.__class__.__name__, id(self), self.filename,
            )
        else:
            msg = "<{:s}.{:s} object at {:#x}, address={:#x}>".format(
                self.__module__, self.__class__.__name__, id(self), self.addr,
            )
        return msg

    def read(self, size):
        if self.fd is not None:
            v = self.fd.read(size)
        elif self.addr is not None:
            v = read_memory(self.addr + self.pos, size)
        else:
            raise
        self.pos += size
        return v

    def seek(self, off):
        if self.fd is not None:
            self.fd.seek(self.seek_init_offset + off, 0)
        elif self.addr is not None:
            self.pos = off
        else:
            raise
        return

    def is_valid(self):
        return self.e_magic == Elf.ELF_MAGIC

    def get_bits(self):
        if self.e_class == Elf.ELF_64_BITS:
            return 64
        if self.e_class == Elf.ELF_32_BITS:
            return 32
        raise

    def get_phdr(self, p_type):
        for phdr in self.phdrs:
            if phdr.p_type == p_type:
                return phdr
        return None

    def get_shdr(self, name):
        for shdr in self.shdrs:
            if shdr.sh_name == name:
                return shdr
        return None

    def read_phdr(self, p_type):
        phdr = self.get_phdr(p_type)
        if phdr is None:
            return None

        if self.filename:
            fd = open(self.filename, "rb")
            fd.seek(phdr.p_offset)
            data = fd.read(phdr.p_filesz)
            fd.close()
            return data

        if self.addr:
            read_addr = phdr.p_vaddr
            if self.is_pie():
                read_addr += self.addr

            data = read_memory(read_addr, phdr.p_memsz)
            return data

        return None

    def read_shdr(self, name):
        shdr = self.get_shdr(name)
        if shdr is None:
            return None

        if self.filename:
            fd = open(self.filename, "rb")
            fd.seek(shdr.sh_offset)
            data = fd.read(shdr.sh_size)
            fd.close()
            return data

        if self.addr:
            if shdr.sh_addr > 0:
                read_addr = shdr.sh_addr
            else:
                # e.g., .comment section of vdso
                """
                [ #] Name                      Type Address Offset Size EntSiz Flags Link Info Align
                ...
                [13] .altinstr_replacement PROGBITS  0x106f 0x106f 0x3c    0x0 AX     0x0  0x0   0x1
                [14] .comment              PROGBITS     0x0 0x10ab 0x25    0x1 MS     0x0  0x0   0x1
                [15] .shstrtab               STRTAB     0x0 0x10d0 0x9e    0x0        0x0  0x0   0x1
                """
                read_addr = shdr.sh_offset

            if self.is_pie():
                read_addr += self.addr

            data = read_memory(read_addr, shdr.sh_size)
            return data

        return None

    def is_static(self):
        # note: static-pie has no PT_INTERP
        return not bool(self.get_phdr(Elf.Phdr.PT_INTERP))

    def has_dynamic(self):
        # note: static-pie has PT_DYNAMIC
        return bool(self.get_phdr(Elf.Phdr.PT_DYNAMIC))

    def is_stripped(self):
        return not bool(self.get_shdr(".symtab"))

    def has_debuginfo(self):
        return bool(self.get_shdr(".debug_info"))

    def has_canary_heuristic(self):
        from gef.core.utils import GefUtil

        try:
            objdump_command = GefUtil.which(Config.get_gef_setting("gef.objdump_command"))
        except FileNotFoundError:
            return None # it means unknown

        # heuristic search
        if self.e_machine in (Elf.EM_X86_64, Elf.EM_386):
            if self.e_machine == Elf.EM_X86_64:
                kw = b"%fs:0x28"
            else: # 32-bit
                kw = b"%gs:0x14"

            proc = subprocess.Popen(
                [objdump_command, "-d", self.filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            for _ in range(0x10000):
                if kw in proc.stdout.readline():
                    proc.kill()
                    return True
            proc.kill()
            return False
        return None # it means unknown

    def is_pie(self):
        return self.e_type == Elf.ET_DYN

    def is_nx(self):
        phdr = self.get_phdr(Elf.Phdr.PT_GNU_STACK)
        if phdr:
            return not bool(phdr.p_flags & Elf.Phdr.PF_X)
        return False

    def is_relro(self):
        # both partial and full have PT_GNU_RELRO
        return bool(self.get_phdr(Elf.Phdr.PT_GNU_RELRO))

    def is_full_relro(self):
        from gef.core.utils import slicer

        data = self.get_dynamic_data()
        if data is None:
            return False

        # check
        for tag, value in slicer(data, 2):
            if tag == 0x18: # DT_BIND_NOW
                return True
            if tag == 0x1e: # DT_FLAGS
                return bool(value & 0x08) # DF_BIND_NOW
        return False

    def vaddr_to_offset(self, vaddr):
        for phdr in self.phdrs:
            if phdr.p_type != Elf.Phdr.PT_LOAD:
                continue
            start = phdr.p_vaddr
            end = phdr.p_vaddr + phdr.p_filesz
            if start <= vaddr < end:
                return phdr.p_offset + vaddr - start
        return None

    def read_cstring_from_vaddr(self, vaddr, size=0x1000):
        if self.filename:
            offset = self.vaddr_to_offset(vaddr)
            if offset is None:
                return None
            with open(self.filename, "rb") as fd:
                fd.seek(offset)
                data = fd.read(size)
            return self.get_string_from_data(data, 0)

        if self.addr:
            addrs = [vaddr]
            if self.is_pie():
                addrs.append(self.addr + vaddr)
            for addr in addrs:
                try:
                    data = read_memory(addr, size)
                    return self.get_string_from_data(data, 0)
                except Exception:
                    continue
        return None

    def get_string_from_data(self, data, offset):
        if offset >= len(data):
            return None
        end = data.find(b"\x00", offset)
        if end < 0:
            return None
        return data[offset:end].decode(errors="replace")

    def get_dynamic_data(self):
        from gef.core.utils import slice_unpack

        data = self.read_shdr(".dynamic")
        if data is None:
            data = self.read_phdr(Elf.Phdr.PT_DYNAMIC)
        if data is None:
            return None
        return slice_unpack(data, self.get_bits() // 8)

    def get_dynamic_value(self, tag_type):
        from gef.core.utils import slicer

        data = self.get_dynamic_data()
        if data is None:
            return None

        for tag, val in slicer(data, 2):
            if tag == 0x0: # DT_NULL
                break
            if tag == tag_type:
                return val
        return None

    def get_dynamic_string(self, tag_type):
        val = self.get_dynamic_value(tag_type)
        if val is None:
            return None
        dynstr = self.read_shdr(".dynstr")
        if dynstr is not None:
            result = self.get_string_from_data(dynstr, val)
            if result is not None:
                return result
        strtab = self.get_dynamic_value(0x5) # DT_STRTAB
        if strtab is None:
            return None
        strsz = self.get_dynamic_value(0xa) # DT_STRSZ
        size = 0x1000
        if strsz is not None and val < strsz:
            size = strsz - val
        return self.read_cstring_from_vaddr(strtab + val, size)

    def has_rpath(self): # noqa
        return self.get_rpath() is not None

    def get_rpath(self):
        return self.get_dynamic_string(0xf) # DT_RPATH

    def has_runpath(self): # noqa
        return self.get_runpath() is not None

    def get_runpath(self):
        return self.get_dynamic_string(0x1d) # DT_RUNPATH

    def has_pac_heuristic(self):
        from gef.core.utils import GefUtil

        pac_ops = [
            b"paciasp", b"pacia", b"pacibsp", b"pacib", b"pacda", b"pacdb", b"pacga",
            b"autiasp", b"autia", b"autibsp", b"autib", b"autda", b"autdb",
            b"retaa", b"retab", b"braa", b"brab", b"blraa", b"blrab",
            b"eretaa", b"eretab", b"ldraa", b"ldrab"
        ]

        try:
            objdump_command = GefUtil.which(Config.get_gef_setting("gef.objdump_command"))
        except FileNotFoundError:
            return None # it means unknown

        proc = subprocess.Popen(
            [objdump_command, "-d", self.filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        for _ in range(0x10000):
            line = proc.stdout.readline().strip()
            if not line:
                continue
            if line.split()[-1] in pac_ops:
                proc.kill()
                return True
        proc.kill()
        return False

    def checksec(self):
        """Check the following security properties of the ELF binary.
        Canary, NX, PIE, RELRO, Fortify, Static, Symbol, Debuginfo, CET,
        RPATH/RUNPATH, and Clang CFI/SafeStack."""

        def exists_sym(dynstr, strtab, keywords):
            if dynstr:
                for kw in keywords:
                    if kw in dynstr:
                        return True
            if strtab:
                for kw in keywords:
                    if kw in strtab:
                        return True
            return False

        def get_features_from_note(note):
            note = note[0x10:] # skip header
            while note:
                pr_type, note = u32(note[:4]), note[4:]
                pr_datasz, note = u32(note[:4]), note[4:]
                pr_data, note = note[:pr_datasz], note[pr_datasz:]

                if pr_type == 0xc000_0002: # GNU_PROPERTY_X86_FEATURE_1_AND
                    if pr_datasz == 4:
                        return u32(pr_data)

                pr_padding = 0
                while (pr_datasz + pr_padding) % runtime.current_arch.ptrsize:
                    pr_padding += 1
                note = note[pr_padding:]
            return 0

        dynstr = self.read_shdr(".dynstr")
        if dynstr:
            dynstr = dynstr.split(b"\0")
        strtab = self.read_shdr(".strtab")
        if strtab:
            strtab = strtab.split(b"\0")

        sec = {}

        # Static
        sec["Static"] = self.is_static()

        # Symbol
        sec["Symbol"] = not self.is_stripped()

        # Debuginfo
        sec["Debuginfo"] = self.has_debuginfo()

        # Canary
        if self.is_static() and self.is_stripped():
            sec["Canary"] = self.has_canary_heuristic()
        else:
            keywords = [
                b"__stack_chk_fail",
                b"__stack_chk_fail_local",
                b"__stack_chk_guard", # for non-x86
                b"__intel_security_cookie", # for intel compiler
            ]
            sec["Canary"] = exists_sym(dynstr, strtab, keywords)

        # NX
        sec["NX"] = self.is_nx()

        # PIE
        sec["PIE"] = self.is_pie()

        # RELRO
        sec["Partial RELRO"] = self.is_relro()
        sec["Full RELRO"] = sec["Partial RELRO"] and self.is_full_relro()

        # Fortify
        if self.is_static() and self.is_stripped():
            sec["Fortify"] = None # it means unknown
        else:
            keywords = [
                b"__memcpy_chk",
                b"__memmove_chk",
                b"__mempcpy_chk",
                b"__memset_chk",
                b"__printf_chk",
                b"__fprintf_chk",
                b"__dprintf_chk",
                b"__sprintf_chk",
                b"__asprintf_chk",
                b"__snprintf_chk",
                b"__wprintf_chk",
                b"__fwprintf_chk",
                b"__swprintf_chk",
                b"__obstack_printf_chk",
                b"__vprintf_chk",
                b"__vfprintf_chk",
                b"__vdprintf_chk",
                b"__vsprintf_chk",
                b"__vasprintf_chk",
                b"__vsnprintf_chk",
                b"__vwprintf_chk",
                b"__vfwprintf_chk",
                b"__vswprintf_chk",
                b"__obstack_vprintf_chk",
                b"__syslog_chk",
                b"__vsyslog_chk",
            ]
            sec["Fortify"] = exists_sym(dynstr, strtab, keywords)

        # CET flags via Ehdr
        if self.e_machine in (Elf.EM_X86_64, Elf.EM_386):
            sec["CET IBT flag"] = False
            sec["CET SHSTK flag"] = False
            note_gnu_property = self.read_phdr(Elf.Phdr.PT_GNU_PROPERTY)
            if note_gnu_property:
                features = get_features_from_note(note_gnu_property)
                sec["CET IBT flag"] = features & 1 # GNU_PROPERTY_X86_FEATURE_1_IBT
                sec["CET SHSTK flag"] = features & 2 # GNU_PROPERTY_X86_FEATURE_1_SHSTK

        # PAC
        if self.e_machine == Elf.EM_AARCH64:
            sec["PAC"] = self.has_pac_heuristic()

        # RPATH
        sec["RPATH"] = self.get_rpath()

        # RUNPATH
        sec["RUNPATH"] = self.get_runpath()

        # Clang CFI (detected only when `-fno-sanitize-trap=all`)
        if self.is_static() and self.is_stripped():
            sec["Clang CFI"] = None
        else:
            sec["Clang CFI"] = exists_sym(dynstr, strtab, ["__ubsan_handle_cfi_"])

        # Clang SafeStack
        if self.is_static() and self.is_stripped():
            sec["Clang SafeStack"] = None
        else:
            sec["Clang SafeStack"] = exists_sym(dynstr, strtab, ["__safestack_init"])
        return sec

    class Phdr:
        # p_type
        PT_NULL               = 0
        PT_LOAD               = 1
        PT_DYNAMIC            = 2
        PT_INTERP             = 3
        PT_NOTE               = 4
        PT_SHLIB              = 5
        PT_PHDR               = 6
        PT_TLS                = 7
        #PT_LOOS              = 0x6000_0000
        PT_GNU_EH_FRAME       = 0x6474_e550
        PT_GNU_STACK          = 0x6474_e551
        PT_GNU_RELRO          = 0x6474_e552
        PT_GNU_PROPERTY       = 0x6474_e553
        PT_GNU_SFRAME         = 0x6474_e554
        #PT_GNU_MBIND_LO      = 0x6474_e555
        #PT_GNU_MBIND_HI      = 0x6474_f554
        #PT_LOSUNW            = 0x6fff_fffa
        PT_SUNWBSS            = 0x6fff_fffa
        PT_SUNWSTACK          = 0x6fff_fffb
        #PT_HISUNW            = 0x6fff_ffff
        #PT_HIOS              = 0x6fff_ffff
        #PT_LOPROC            = 0x7000_0000
        #PT_HIPROC            = 0x7fff_ffff
        PT_AARCH64_ARCHEXT    = 0x7000_0000 # noqa: F841
        PT_AARCH64_MEMTAG_MTE = 0x7000_0002 # noqa: F841
        PT_ARM_ARCHEXT        = 0x7000_0000 # noqa: F841
        PT_ARM_EXIDX          = 0x7000_0001 # noqa: F841
        PT_HP_TLS             = 0x6000_0000 # noqa: F841
        PT_HP_CORE_NONE       = 0x6000_0001 # noqa: F841
        PT_HP_CORE_VERSION    = 0x6000_0002 # noqa: F841
        PT_HP_CORE_KERNEL     = 0x6000_0003 # noqa: F841
        PT_HP_CORE_COMM       = 0x6000_0004 # noqa: F841
        PT_HP_CORE_PROC       = 0x6000_0005 # noqa: F841
        PT_HP_CORE_LOADABLE   = 0x6000_0006 # noqa: F841
        PT_HP_CORE_STACK      = 0x6000_0007 # noqa: F841
        PT_HP_CORE_SHM        = 0x6000_0008 # noqa: F841
        PT_HP_CORE_MMF        = 0x6000_0009 # noqa: F841
        PT_HP_PARALLEL        = 0x6000_0010 # noqa: F841
        PT_HP_FASTBIND        = 0x6000_0011 # noqa: F841
        PT_HP_OPT_ANNOT       = 0x6000_0012 # noqa: F841
        PT_HP_HSL_ANNOT       = 0x6000_0013 # noqa: F841
        PT_HP_STACK           = 0x6000_0014 # noqa: F841
        PT_HP_CORE_UTSNAME    = 0x6000_0015 # noqa: F841
        PT_IA_64_HP_OPT_ANOT  = 0x6000_0012 # noqa: F841
        PT_IA_64_HP_HSL_ANOT  = 0x6000_0013 # noqa: F841
        PT_IA_64_HP_STACK     = 0x6000_0014 # noqa: F841
        PT_IA_64_ARCHEXT      = 0x7000_0000 # noqa: F841
        PT_IA_64_UNWIND       = 0x7000_0001 # noqa: F841
        PT_MIPS_REGINFO       = 0x7000_0000 # noqa: F841
        PT_MIPS_RTPROC        = 0x7000_0001 # noqa: F841
        PT_MIPS_OPTIONS       = 0x7000_0002 # noqa: F841
        PT_MIPS_ABIFLAGS      = 0x7000_0003 # noqa: F841
        PT_PARISC_ARCHEXT     = 0x7000_0000 # noqa: F841
        PT_PARISC_UNWIND      = 0x7000_0001 # noqa: F841
        PT_PARISC_WEAKORDER   = 0x7000_0002 # noqa: F841
        PT_RISCV_ATTRIBUTES   = 0x7000_0003 # noqa: F841
        PT_S390_PGSTE         = 0x7000_0000 # noqa: F841

        # p_flags
        PF_X                = 1
        PF_W                = 2
        PF_R                = 4
        PF_ARM_SB           = 0x1000_0000 # noqa: F841
        PF_ARM_PI           = 0x2000_0000 # noqa: F841
        PF_ARM_ABS          = 0x4000_0000 # noqa: F841
        PF_HP_CODE          = 0x0004_0000 # noqa: F841
        PF_HP_MODIFY        = 0x0008_0000 # noqa: F841
        PF_HP_PAGE_SIZE     = 0x0010_0000 # noqa: F841
        PF_HP_FAR_SHARED    = 0x0020_0000 # noqa: F841
        PF_HP_NEAR_SHARED   = 0x0040_0000 # noqa: F841
        PF_HP_LAZYSWAP      = 0x0080_0000 # noqa: F841
        PF_HP_CODE_DEPR     = 0x0100_0000 # noqa: F841
        PF_HP_MODIFY_DEPR   = 0x0200_0000 # noqa: F841
        PF_HP_LAZYSWAP_DEPR = 0x0400_0000 # noqa: F841
        PF_HP_SBP           = 0x0800_0000 # noqa: F841
        PF_IA_64_NORECOV    = 0x8000_0000 # noqa: F841
        PF_OVERRAY          = 0x0800_0000 # noqa: F841
        PF_PARISC_SBP       = 0x0800_0000 # noqa: F841

        p_type   = None
        p_flags  = None
        p_offset = None
        p_vaddr  = None
        p_paddr  = None
        p_filesz = None
        p_memsz  = None
        p_align  = None

        def __init__(self, elf, off):
            if elf is None:
                return None
            elf.seek(off)
            endian = "<" if elf.e_endianness == Elf.LITTLE_ENDIAN else ">"
            if elf.e_class == Elf.ELF_64_BITS:
                self.p_type, self.p_flags, self.p_offset = struct.unpack("{}IIQ".format(endian), elf.read(16))
                self.p_vaddr, self.p_paddr = struct.unpack("{}QQ".format(endian), elf.read(16))
                self.p_filesz, self.p_memsz, self.p_align = struct.unpack("{}QQQ".format(endian), elf.read(24))
            else:
                self.p_type, self.p_offset = struct.unpack("{}II".format(endian), elf.read(8))
                self.p_vaddr, self.p_paddr = struct.unpack("{}II".format(endian), elf.read(8))
                self.p_filesz, self.p_memsz, = struct.unpack("{}II".format(endian), elf.read(8))
                self.p_flags, self.p_align = struct.unpack("{}II".format(endian), elf.read(8))

        def __repr__(self):
            for e in dir(self):
                if e.startswith("PT_"):
                    if self.p_type == getattr(self, e):
                        return "<{:s}.{:s} object at {:#x}, p_type={:s}>".format(
                            self.__module__, self.__class__.__name__, id(self), e,
                        )
            return "<{:s}.{:s} object at {:#x}, p_type={:#x}>".format(
                self.__module__, self.__class__.__name__, id(self), self.p_type,
            )

    class Shdr:
        # sh_type
        SHT_NULL                           = 0
        SHT_PROGBITS                       = 1
        SHT_SYMTAB                         = 2
        SHT_STRTAB                         = 3
        SHT_RELA                           = 4
        SHT_HASH                           = 5
        SHT_DYNAMIC                        = 6
        SHT_NOTE                           = 7
        SHT_NOBITS                         = 8
        SHT_REL                            = 9
        SHT_SHLIB                          = 10
        SHT_DYNSYM                         = 11
        SHT_INIT_ARRAY                     = 14
        SHT_FINI_ARRAY                     = 15
        SHT_PREINIT_ARRAY                  = 16
        SHT_GROUP                          = 17
        SHT_SYMTAB_SHNDX                   = 18
        SHT_RELR                           = 19
        #SHT_LOOS                          = 0x6000_0000
        SHT_ANDROID_REL                    = 0x6000_0001
        SHT_ANDROID_RELA                   = 0x6000_0002
        SHT_HP_OVLBITS                     = 0x6000_0000 # noqa: F841
        SHT_HP_DLKM                        = 0x6000_0001 # noqa: F841
        SHT_HP_COMDAT                      = 0x6000_0002 # noqa: F841
        SHT_HP_OBJDICT                     = 0x6000_0003 # noqa: F841
        SHT_HP_ANNOT                       = 0x6000_0004 # noqa: F841
        SHT_IA_64_VMS_TRACE                = 0x6000_0000 # noqa: F841
        SHT_IA_64_VMS_TIE_SIGNATURES       = 0x6000_0001 # noqa: F841
        SHT_IA_64_VMS_DEBUG                = 0x6000_0002 # noqa: F841
        SHT_IA_64_VMS_DEBUG_STR            = 0x6000_0003 # noqa: F841
        SHT_IA_64_VMS_LINKAGES             = 0x6000_0004 # noqa: F841
        SHT_IA_64_VMS_SYMBOL_VECTOR        = 0x6000_0005 # noqa: F841
        SHT_IA_64_VMS_FIXUP                = 0x6000_0006 # noqa: F841
        SHT_IA_64_VMS_DISPLAY_NAME_INFO    = 0x6000_0007 # noqa: F841
        SHT_GNU_INCREMENTAL_INPUTS         = 0x6fff_4700
        SHT_LLVM_ODRTAB                    = 0x6fff_4c00
        SHT_LLVM_LINKER_OPTIONS            = 0x6fff_4c01
        SHT_LLVM_CALL_GRAPH_PROFILE        = 0x6fff_4c02
        SHT_LLVM_ADDRSIG                   = 0x6fff_4c03
        SHT_LLVM_DEPENDENT_LIBRARIES       = 0x6fff_4c04
        SHT_LLVM_SYMPART                   = 0x6fff_4c05
        SHT_LLVM_PART_EHDR                 = 0x6fff_4c06
        SHT_LLVM_PART_PHDR                 = 0x6fff_4c07
        SHT_LLVM_BB_ADDR_MAP_V0            = 0x6fff_4c08
        SHT_LLVM_CALL_GRAPH_PROFILE        = 0x6fff_4c09
        SHT_LLVM_BB_ADDR_MAP               = 0x6fff_4c0a
        SHT_LLVM_OFFLOADING                = 0x6fff_4c0b
        SHT_LLVM_LTO                       = 0x6fff_4c0c
        SHT_ANDROID_RELR                   = 0x6fff_ff00
        SHT_GNU_ATTRIBUTES                 = 0x6fff_fff5
        SHT_GNU_HASH                       = 0x6fff_fff6
        SHT_GNU_LIBLIST                    = 0x6fff_fff7
        SHT_CHECKSUM                       = 0x6fff_fff8
        #SHT_LOSUNW                        = 0x6fff_fffa
        SHT_SUNW_move                      = 0x6fff_fffa
        SHT_SUNW_COMDAT                    = 0x6fff_fffb
        SHT_SUNW_syminfo                   = 0x6fff_fffc
        SHT_GNU_verdef                     = 0x6fff_fffd
        SHT_GNU_verneed                    = 0x6fff_fffe
        SHT_GNU_versym                     = 0x6fff_ffff
        #SHT_HISUNW                        = 0x6fff_ffff
        #SHT_HIOS                          = 0x6fff_ffff
        #SHT_LOPROC                        = 0x7000_0000
        SHT_AARCH64_ATTRIBUTES             = 0x7000_0003 # noqa: F841
        SHT_AARCH64_AUTH_RELR              = 0x7000_0004 # noqa: F841
        SHT_AARCH64_MEMTAG_GLOBALS_STATIC  = 0x7000_0007 # noqa: F841
        SHT_AARCH64_MEMTAG_GLOBALS_DYNAMIC = 0x7000_0008 # noqa: F841
        SHT_ALPHA_DEBUG                    = 0x7000_0001 # noqa: F841
        SHT_ALPHA_REGINFO                  = 0x7000_0002 # noqa: F841
        SHT_ARC_ATTRIBUTES                 = 0x7000_0001 # noqa: F841
        SHT_ARM_EXIDX                      = 0x7000_0001 # noqa: F841
        SHT_ARM_PREEMPTMAP                 = 0x7000_0002 # noqa: F841
        SHT_ARM_ATTRIBUTES                 = 0x7000_0003 # noqa: F841
        SHT_ARM_DEBUGOVERLAY               = 0x7000_0004 # noqa: F841
        SHT_ARM_OVERLAYSECTION             = 0x7000_0005 # noqa: F841
        SHT_C6000_UNWIND                   = 0x7000_0001 # noqa: F841
        SHT_C6000_PREEMPTMAP               = 0x7000_0002 # noqa: F841
        SHT_C6000_ATTRIBUTES               = 0x7000_0003 # noqa: F841
        SHT_CSKY_ATTRIBUTES                = 0x7000_0001 # noqa: F841
        SHT_IA_64_EXT                      = 0x7000_0000 # noqa: F841
        SHT_IA_64_UNWIND                   = 0x7000_0001 # noqa: F841
        SHT_IA_64_LOPSREG                  = 0x7800_0000 # noqa: F841
        SHT_IA_64_HIPSREG                  = 0x78ff_ffff # noqa: F841
        SHT_IA_64_PRIORITY_INIT            = 0x7900_0000 # noqa: F841
        SHT_MIPS_LIBLIST                   = 0x7000_0000 # noqa: F841
        SHT_MIPS_MSYM                      = 0x7000_0001 # noqa: F841
        SHT_MIPS_CONFLICT                  = 0x7000_0002 # noqa: F841
        SHT_MIPS_GPTAB                     = 0x7000_0003 # noqa: F841
        SHT_MIPS_UCODE                     = 0x7000_0004 # noqa: F841
        SHT_MIPS_DEBUG                     = 0x7000_0005 # noqa: F841
        SHT_MIPS_REGINFO                   = 0x7000_0006 # noqa: F841
        SHT_MIPS_PACKAGE                   = 0x7000_0007 # noqa: F841
        SHT_MIPS_PACKSYM                   = 0x7000_0008 # noqa: F841
        SHT_MIPS_RELD                      = 0x7000_0009 # noqa: F841
        SHT_MIPS_IFACE                     = 0x7000_000b # noqa: F841
        SHT_MIPS_CONTENT                   = 0x7000_000c # noqa: F841
        SHT_MIPS_OPTIONS                   = 0x7000_000d # noqa: F841
        SHT_MIPS_SHDR                      = 0x7000_0010 # noqa: F841
        SHT_MIPS_FDESC                     = 0x7000_0011 # noqa: F841
        SHT_MIPS_EXTSYM                    = 0x7000_0012 # noqa: F841
        SHT_MIPS_DENSE                     = 0x7000_0013 # noqa: F841
        SHT_MIPS_PDESC                     = 0x7000_0014 # noqa: F841
        SHT_MIPS_LOCSYM                    = 0x7000_0015 # noqa: F841
        SHT_MIPS_AUXSYM                    = 0x7000_0016 # noqa: F841
        SHT_MIPS_OPTSYM                    = 0x7000_0017 # noqa: F841
        SHT_MIPS_LOCSTR                    = 0x7000_0018 # noqa: F841
        SHT_MIPS_LINE                      = 0x7000_0019 # noqa: F841
        SHT_MIPS_RFDESC                    = 0x7000_001a # noqa: F841
        SHT_MIPS_DELTASYM                  = 0x7000_001b # noqa: F841
        SHT_MIPS_DELTAINST                 = 0x7000_001c # noqa: F841
        SHT_MIPS_DELTACLASS                = 0x7000_001d # noqa: F841
        SHT_MIPS_DWARF                     = 0x7000_001e # noqa: F841
        SHT_MIPS_DELTADECL                 = 0x7000_001f # noqa: F841
        SHT_MIPS_SYMBOL_LIB                = 0x7000_0020 # noqa: F841
        SHT_MIPS_EVENTS                    = 0x7000_0021 # noqa: F841
        SHT_MIPS_TRANSLATE                 = 0x7000_0022 # noqa: F841
        SHT_MIPS_PIXIE                     = 0x7000_0023 # noqa: F841
        SHT_MIPS_XLATE                     = 0x7000_0024 # noqa: F841
        SHT_MIPS_XLATE_DEBUG               = 0x7000_0025 # noqa: F841
        SHT_MIPS_WHIRL                     = 0x7000_0026 # noqa: F841
        SHT_MIPS_EH_REGION                 = 0x7000_0027 # noqa: F841
        SHT_MIPS_XLATE_OLD                 = 0x7000_0028 # noqa: F841
        SHT_MIPS_PDR_EXCEPTION             = 0x7000_0029 # noqa: F841
        SHT_MIPS_ABIFLAGS                  = 0x7000_002a # noqa: F841
        SHT_MIPS_XHASH                     = 0x7000_002b # noqa: F841
        SHT_MSP430_ATTRIBUTES              = 0x7000_0003 # noqa: F841
        SHT_MSP430_SEC_FLAGS               = 0x7000_0005 # noqa: F841
        SHT_MSP430_SYM_ALIASES             = 0x7000_0006 # noqa: F841
        SHT_NFP_MECONFIG                   = 0x7000_0001 # noqa: F841
        SHT_NFP_INITREG                    = 0x7000_0002 # noqa: F841
        SHT_PARISC_EXT                     = 0x7000_0000 # noqa: F841
        SHT_PARISC_UNWIND                  = 0x7000_0001 # noqa: F841
        SHT_PARISC_DOC                     = 0x7000_0002 # noqa: F841
        SHT_PARISC_ANNOT                   = 0x7000_0003 # noqa: F841
        SHT_PARISC_DLKM                    = 0x7000_0004 # noqa: F841
        SHT_PARISC_SYMEXTN                 = 0x7000_0008 # noqa: F841
        SHT_PARISC_STUBS                   = 0x7000_0009 # noqa: F841
        SHT_RISCV_ATTRIBUTES               = 0x7000_0003 # noqa: F841
        SHT_V850_SCOMMON                   = 0x7000_0000 # noqa: F841
        SHT_V850_TCOMMON                   = 0x7000_0001 # noqa: F841
        SHT_V850_ZCOMMON                   = 0x7000_0002 # noqa: F841
        SHT_X86_64_UNWIND                  = 0x7000_0001 # noqa: F841
        SHT_TI_ICODE                       = 0x7F00_0000 # noqa: F841
        SHT_TI_XREF                        = 0x7F00_0001 # noqa: F841
        SHT_TI_HANDLER                     = 0x7F00_0002 # noqa: F841
        SHT_TI_INITINFO                    = 0x7F00_0003 # noqa: F841
        SHT_TI_PHATTRS                     = 0x7F00_0004 # noqa: F841
        SHT_ORDERED                        = 0x7fff_ffff # noqa: F841
        #SHT_HIPROC                        = 0x7fff_ffff
        #SHT_LOUSER                        = 0x8000_0000
        SHT_NFP_UDEBUG                     = 0x8000_0000 # noqa: F841
        SHT_RENESAS_IOP                    = 0x8000_0000 # noqa: F841
        #SHT_HIUSER                        = 0x8fff_ffff
        SHT_RENESAS_INFO                   = 0xa000_0000 # noqa: F841

        # sh_flags
        SHF_WRITE            = 1
        SHF_ALLOC            = 2
        SHF_EXECINSTR        = 4
        SHF_MERGE            = 0x10
        SHF_STRINGS          = 0x20
        SHF_INFO_LINK        = 0x40
        SHF_LINK_ORDER       = 0x80
        SHF_OS_NONCONFORMING = 0x100
        SHF_GROUP            = 0x200
        SHF_TLS              = 0x400
        SHF_COMPRESSED       = 0x800
        SHF_RELA_LIVEPATCH   = 0x0010_0000 # noqa: F841
        SHF_RO_AFTER_INIT    = 0x0020_0000 # noqa: F841
        SHF_ORDERED          = 0x4000_0000 # noqa: F841
        SHF_EXCLUDE          = 0x8000_0000
        SHF_MIPS_NODUPES     = 0x0100_0000 # noqa: F841
        SHF_MIPS_NAMES       = 0x0200_0000 # noqa: F841
        SHF_MIPS_LOCAL       = 0x0400_0000 # noqa: F841
        SHF_MIPS_NOSTRIP     = 0x0800_0000 # noqa: F841
        SHF_MIPS_GPREL       = 0x1000_0000 # noqa: F841
        SHF_MIPS_MERGE       = 0x2000_0000 # noqa: F841
        SHF_MIPS_ADDR        = 0x4000_0000 # noqa: F841
        SHF_MIPS_STRING      = 0x8000_0000 # noqa: F841
        SHF_PARISC_SHORT     = 0x2000_0000 # noqa: F841
        SHF_PARISC_HUGE      = 0x4000_0000 # noqa: F841
        SHF_PARISC_SBP       = 0x8000_0000 # noqa: F841
        SHF_ALPHA_GPREL      = 0x1000_0000 # noqa: F841
        SHF_IA_64_SHORT      = 0x1000_0000 # noqa: F841

        sh_name              = None
        sh_type              = None
        sh_flags             = None
        sh_addr              = None
        sh_offset            = None
        sh_size              = None
        sh_link              = None
        sh_info              = None
        sh_addralign         = None
        sh_entsize           = None

        def __init__(self, elf, off):
            if elf is None:
                return None
            elf.seek(off)
            endian = "<" if elf.e_endianness == Elf.LITTLE_ENDIAN else ">"
            if elf.e_class == Elf.ELF_64_BITS:
                self.sh_name, self.sh_type, self.sh_flags = struct.unpack("{}IIQ".format(endian), elf.read(16))
                self.sh_addr, self.sh_offset = struct.unpack("{}QQ".format(endian), elf.read(16))
                self.sh_size, self.sh_link, self.sh_info = struct.unpack("{}QII".format(endian), elf.read(16))
                self.sh_addralign, self.sh_entsize = struct.unpack("{}QQ".format(endian), elf.read(16))
            else:
                self.sh_name, self.sh_type, self.sh_flags = struct.unpack("{}III".format(endian), elf.read(12))
                self.sh_addr, self.sh_offset = struct.unpack("{}II".format(endian), elf.read(8))
                self.sh_size, self.sh_link, self.sh_info = struct.unpack("{}III".format(endian), elf.read(12))
                self.sh_addralign, self.sh_entsize = struct.unpack("{}II".format(endian), elf.read(8))

            # name
            stroff = elf.e_shoff + elf.e_shentsize * elf.e_shstrndx

            if elf.e_class == Elf.ELF_64_BITS:
                elf.seek(stroff + 16 + 8)
                offset = struct.unpack("{}Q".format(endian), elf.read(8))[0]
            else:
                elf.seek(stroff + 12 + 4)
                offset = struct.unpack("{}I".format(endian), elf.read(4))[0]
            elf.seek(offset + self.sh_name)
            self.sh_name = ""
            while True:
                c = ord(elf.read(1))
                if c == 0:
                    break
                self.sh_name += chr(c)
            return

        def __repr__(self):
            return '<{:s}.{:s} object at {:#x}, sh_name="{:s}">'.format(
                self.__module__, self.__class__.__name__, id(self), self.sh_name,
            )


class Checksec:
    """Manage checksec related functions."""

    @staticmethod
    @Cache.cache_until_next
    def get_cet_status_old_interface():
        from gef.core.memory import write_memory

        # https://lore.kernel.org/lkml/1531342544.15351.37.camel@intel.com/
        sp = runtime.current_arch.sp
        mem = {}

        # backup
        for i in range(3):
            # *addr = SHSTK/IBT status
            # *(addr + 1) = SHSTK base address
            # *(addr + 2) = SHSTK size
            addr = sp + runtime.current_arch.ptrsize * i
            mem[addr] = read_memory(addr, runtime.current_arch.ptrsize)

        res = gdb.execute("call-syscall arch_prctl 0x3001 {:#x}".format(sp), to_string=True) # ARCH_CET_STATUS
        output_line = res.splitlines()[-1]
        ret = int(output_line.split()[2], 0)

        sp_value = read_int_from_memory(sp)

        # revert
        for addr, data in mem.items():
            write_memory(addr, data)

        # check ret
        if ret != 0:
            return None
        return sp_value

    @staticmethod
    @Cache.cache_until_next
    def get_cet_status_new_interface():
        from gef.core.memory import write_memory

        # https://www.kernel.org/doc/html/next/arch/x86/shstk.html
        sp = runtime.current_arch.sp
        mem = {}

        # backup
        for i in range(1):
            # *addr = SHSTK status
            addr = sp + runtime.current_arch.ptrsize * i
            mem[addr] = read_memory(addr, runtime.current_arch.ptrsize)

        res = gdb.execute("call-syscall arch_prctl 0x5005 {:#x}".format(sp), to_string=True) # ARCH_SHSTK_STATUS
        output_line = res.splitlines()[-1]
        ret = int(output_line.split()[2], 0)

        sp_value = read_int_from_memory(sp)

        # revert
        for addr, data in mem.items():
            write_memory(addr, data)

        if ret != 0:
            return None
        return sp_value

    @staticmethod
    @Cache.cache_until_next
    def get_cet_status_via_procfs():
        from gef.core.process import Path, Pid, is_remote_debug

        # https://www.kernel.org/doc/html/next/arch/x86/shstk.html
        dic = {}
        if is_remote_debug():
            if Pid.get_pid(remote=True):
                remote_status = "/proc/{:d}/status".format(Pid.get_pid(remote=True))
            data = Path.read_remote_file(remote_status, as_byte=True) # qemu-user is failed here, it is ok
            if not data:
                return None
        else:
            if Pid.get_pid():
                local_status = "/proc/{:d}/status".format(Pid.get_pid())
            data = open(local_status, "rb").read()
            if not data:
                return None

        if b"x86_Thread_features:" not in data:
            return False # unsupported

        dic["shstk"] = b"x86_Thread_features: shstk" in data
        dic["shstk lock"] = b"x86_Thread_features_locked: shstk" in data
        return dic

    @staticmethod
    def get_mte_status():
        from gef.core.auxv import Auxv

        auxv = Auxv.get_auxiliary_values()
        HWCAP2_MTE = 1 << 18
        if auxv and "AT_HWCAP2" in auxv and (auxv["AT_HWCAP2"] & HWCAP2_MTE) == 0:
            return None # Unsupported
        res = gdb.execute("call-syscall prctl 0x38 0 0 0 0", to_string=True) # PR_GET_TAGGED_ADDR_CTRL
        output_line = res.splitlines()[-1]
        ret = int(output_line.split()[2], 0)

        pQ = lambda a: struct.pack("<Q", a & 0xffff_ffff_ffff_ffff)
        uq = lambda a: struct.unpack("<q", a)[0]
        u2i = lambda a: uq(pQ(a))
        return u2i(ret)

    @staticmethod
    def get_pac_status():
        from gef.core.auxv import Auxv

        auxv = Auxv.get_auxiliary_values()
        HWCAP_PACA = 1 << 30
        HWCAP_PACG = 1 << 31
        if auxv and "AT_HWCAP" in auxv and (auxv["AT_HWCAP"] & (HWCAP_PACA | HWCAP_PACG)) == 0:
            return None # Unsupported
        res = gdb.execute("call-syscall prctl 0x3d 0 0 0 0", to_string=True) # PR_PAC_GET_ENABLED_KEYS
        output_line = res.splitlines()[-1]
        ret = int(output_line.split()[2], 0)

        pQ = lambda a: struct.pack("<Q", a & 0xffff_ffff_ffff_ffff)
        uq = lambda a: struct.unpack("<q", a)[0]
        u2i = lambda a: uq(pQ(a))
        return u2i(ret)
