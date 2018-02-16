"""
efiutils.py

Some utility functions to aid with the reverse engineering of EFI executables.

See the following URL for more info and the latest version:
https://github.com/snarez/ida-efiutils
"""

import copy
import struct

import idaapi
import idautils
import ida_bytes
import ida_entry
import ida_idp
import ida_kernwin
import ida_lines
import ida_name
import ida_pro
import ida_segment
import ida_struct
import ida_ua

import efiguids


MAX_STACK_DEPTH = 1
IMAGE_HANDLE_NAME       = 'gImageHandle'
SYSTEM_TABLE_NAME       = 'gSystemTable'
SYSTEM_TABLE_STRUCT     = 'EFI_SYSTEM_TABLE'
BOOT_SERVICES_NAME      = 'gBootServices'
BOOT_SERVICES_STRUCT    = 'EFI_BOOT_SERVICES'
RUNTIME_SERVICES_NAME   = 'gRuntimeServices'
RUNTIME_SERVICES_STRUCT = 'EFI_RUNTIME_SERVICES'

local_guids = { }


class GUID:
    Data1 = None
    Data2 = None
    Data3 = None
    Data4 = None

    def __init__(self, default=None, bytes=None, string=None, array=None):
        if isinstance(default, basestring):
            string = default
        elif isinstance(default, list):
            array = default

        if bytes != None:
            (self.Data1, self.Data2, self.Data3, d40, d41, d42, d43, d44, d45, d46, d47) = \
                struct.unpack("<IHH8B", bytes)
            self.Data4 = [d40, d41, d42, d43, d44, d45, d46, d47]
            self.bytes = bytes
        elif string != None:
            s = string.split('-')
            self.Data1 = int(s[0], 16)
            self.Data2 = int(s[1], 16)
            self.Data3 = int(s[2], 16)
            self.Data4 = struct.unpack('BBBBBBBB', struct.pack('>Q', int(''.join(s[3:]), 16)))
        elif array != None:
            (self.Data1, self.Data2, self.Data3, self.Data4) = (array[0], array[1], array[2], array[3:])

    def __str__(self):
        return "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % tuple(self.array())

    def bytes(self):
        return self.bytes

    def string(self):
        return str(self)

    def array(self):
        d = self.Data4
        return [self.Data1, self.Data2, self.Data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]


def go():
    rename_tables()
    update_structs()
    rename_guids()


def rename_tables():
    """
    Look at the entry point function and find where the SystemTable parameter is stored, along with the
    RuntimeServices and BootServices tables. Rename the globals these are stored in.

    The entry point for an EFI executable is called like this:
    EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE * SystemTable)

    ImageHandle is passed in rcx, SystemTable is passed in rdx.
    """
    regs = {}
    regs['im'] = ['rcx']
    regs['st'] = ['rdx']
    regs['bs'] = []
    regs['rs'] = []

    entry = ida_entry.get_entry_ordinal(0)

    rename_tables_internal(entry, regs)


def rename_tables_internal(ea, regs, stackdepth=0):
    names = {'im': IMAGE_HANDLE_NAME, 'st': SYSTEM_TABLE_NAME, 'bs': BOOT_SERVICES_NAME, 'rs': RUNTIME_SERVICES_NAME}

    print "Processing function at 0x{:08x}".format(ea)
 
    for item in idautils.FuncItems(ea):
        inst = idautils.DecodeInstruction(item)

        # Bail out if we hit a call
        if inst.get_canon_mnem() == "call":
            if stackdepth == MAX_STACK_DEPTH:
                print "  - Hit stack depth limit, bailing!"
                return
            else:
                if inst.Op1.type in [ida_ua.o_imm, ida_ua.o_far, ida_ua.o_near]:
                    # TODO : Currently assuming that the registry will be inaffected by calls
                    rename_tables_internal(inst.Op1.addr, copy.deepcopy(regs), stackdepth+1)
                else:
                    print "  - Can't follow call, bailing!"
                    return

        if inst.get_canon_mnem() in ["mov", "lea"]:
            # Rename data
            for key in names:
                if get_reg_str(inst.Op2) in regs[key] and inst.Op1.type == ida_ua.o_mem:
                    print "  - Found a copy to a memory address for {}, updating: {}".format(names[key], disasm(inst.ea))
                    ida_name.set_name(inst.Op1.addr, names[key])
                    break

            # Eliminate overwritten registers
            for key in names:
                if get_reg_str(inst.Op1) in regs[key] and get_reg_str(inst.Op2) not in regs[key]:
                    print "  - Untracking register {} for {}: {}".format(get_reg_str(inst.Op1), names[key], disasm(inst.ea))
                    regs[key].remove(get_reg_str(inst.Op1))

            # Keep track of registers containing the EFI tables etc
            if get_reg_str(inst.Op2) in regs['im'] and inst.Op1.type == ida_ua.o_reg and get_reg_str(inst.Op1) not in regs['im']:
                # A tracked register was copied to a new register, track the new one
                print "  - Tracking register {} for image handle: {}".format(get_reg_str(inst.Op1), disasm(inst.ea))
                regs['im'].append(get_reg_str(inst.Op1))
            if get_reg_str(inst.Op2) in regs['st'] and inst.Op1.type == ida_ua.o_reg and get_reg_str(inst.Op1) not in regs['st']:
                # A tracked register was copied to a new register, track the new one
                print "  - Tracking register {} for system table: {}".format(get_reg_str(inst.Op1), disasm(inst.ea))
                regs['st'].append(get_reg_str(inst.Op1))
            if inst.Op2.type == ida_ua.o_displ and ida_idp.get_reg_name(inst.Op2.reg, 8) in regs['st']:
                # A tracked register was used in a right operand with a displacement
                offset = inst.Op2.addr
                if offset == 0x60:
                    print "  - Tracking register {} for boot services table: {}".format(get_reg_str(inst.Op1), disasm(inst.ea))
                    regs['bs'].append(get_reg_str(inst.Op1))
                elif offset == 0x58:
                    print "  - Tracking register {} for runtime services table: {}".format(get_reg_str(inst.Op1), disasm(inst.ea))
                    regs['rs'].append(get_reg_str(inst.Op1))

                apply_struct_offset(inst, 1, SYSTEM_TABLE_STRUCT)


def update_structs():
    """Update xrefs to the major EFI tables to be struct offsets."""
    structs = {SYSTEM_TABLE_NAME: SYSTEM_TABLE_STRUCT, BOOT_SERVICES_NAME: BOOT_SERVICES_STRUCT,
               RUNTIME_SERVICES_NAME: RUNTIME_SERVICES_STRUCT}
    for key in structs:
        addr = get_name_ea(0, key);
        if addr == BADADDR:
            print "Couldn't find address for " + key
        else:
            print "Updating structure references for {} ({})".format(key, structs[key])
            update_struct_offsets(addr, key, structs[key])


def update_struct_offsets(data_addr, struct_label, struct_name):
    """
    Find xrefs to a struct pointer and change all the offsets to be struct offsets. This is useful for updating
    references to function pointers in EFI tables.

    For example:
    mov     rax, cs:qword_whatever
    call    qword ptr [rax+150h]

    Becomes:
    mov     rax, cs:gBootServices
    call    [rax+EFI_BOOT_SERVICES.UninstallMultipleProtocolInterfaces]

    Parameters:
    addr        - The address of the struct pointer global
    struct_name - The name of the structure to use for offsets
    """

    # Find all xrefs to this data in the code
    xrefs = list(idautils.DataRefsTo(data_addr))
    print "Found {} xrefs".format(len(xrefs))
    print "Struct name : {}".format(struct_name)
    # Process xrefs
    for xref in xrefs:
        inst = idautils.DecodeInstruction(xref)
        # We're only interested in xrefs in code where the left operand is a register, and the right operand is the
        # memory address of our data structure.
        if inst.Op1.type == o_reg and inst.Op2.type == o_mem and ida_name.get_name(inst.Op2.addr) == struct_label:
            print "Processing xref from 0x{:08x}: {}".format(xref, disasm(xref))
            update_struct_offsets_for_xref(xref, struct_name)
        else:
            print "Too hard basket - xref from 0x{:08x}: {}".format(xref, disasm(xref))


def update_struct_offsets_for_xref(xref, struct_name):
    regs = {}
    regs['hndl'] = []
    regs['ptr'] = []

    inst = idautils.DecodeInstruction(xref)
    # Are we looking at a handle or a pointer?
    if inst.get_canon_mnem() == "mov":
        regs['ptr'].append(get_reg_str(inst.Op1))
        print "  - Tracking pointer register {} at 0x{:08x}: {}".format(regs['ptr'][0], xref, disasm(xref))
    elif inst.get_canon_mnem() == "lea":
        regs['hndl'].append(get_reg_str(inst.Op1))
        print "  - Tracking handle register {} at 0x{:08x}: {}".format(regs['hndl'][0], xref, disasm(xref))

    # Get the rest of the instructions in this function
    items = list(idautils.FuncItems(xref))
    if len(items):
        idx = items.index(xref)+1
        items = items[idx:]
    else:
        print "  - Xref at 0x{:08x} wasn't marked as a function".format(xref)
        cur = ida_bytes.next_head(xref, idaapi.cvar.inf.maxEA)
        while True:
            if cur not in items:
                items.append(cur)
                print "adding 0x{:08x}: ".format(cur, disasm(cur))

            inst = idautils.DecodeInstruction(cur)
            if inst.get_canon_mnem() in ['call', 'jmp', 'retn']:
                break
            cur = ida_bytes.next_head(cur, idaapi.cvar.inf.maxEA)

    # Iterate through the rest of the instructions in this function looking for tracked registers with a displacement
    for item in items:
        regs['nhndl'] = []
        regs['nptr'] = []

        inst = idautils.DecodeInstruction(item)
        # Update any call instruction with a displacement from our register
        for op_no, op in enumerate(inst.Operands):
            if op_no == 2:
                break
            if op.type == o_displ and ida_idp.get_reg_name(op.reg, 8) in regs['ptr']:
                print "  - Updating operand {} in instruction at 0x{:08x}: {}".format(get_op_str(inst.ea, op_no), item, disasm(item))
                apply_struct_offset(inst, op_no, struct_name)

        # If we find a mov instruction that copies a tracked register, track the new register
        if inst.get_canon_mnem() == 'mov':
            if get_reg_str(inst.Op2) in regs['ptr'] and get_reg_str(inst.Op1) not in regs['ptr']:
                print "  - Copied tracked register at 0x{:08x}, tracking register {}".format(item, get_reg_str(inst.Op1))
                regs['ptr'].append(get_reg_str(inst.Op1))
                regs['nptr'].append(get_reg_str(inst.Op1))
            if get_reg_str(inst.Op2) in regs['hndl'] and get_reg_str(inst.Op1) not in regs['hndl']:
                print "  - Copied tracked register at 0x{:08x}, tracking register {}".format(item, get_reg_str(inst.Op1))
                regs['hndl'].append(get_reg_str(inst.Op1))
                regs['nhndl'].append(get_reg_str(inst.Op1))

        # If we find a mov instruction that dereferences a handle, track the destination register
        for reg in regs['hndl']:
            if get_reg_str(inst.Op2) == "[{}]".format(reg) and inst.get_canon_mnem() == 'mov' and get_reg_str(inst.Op1) not in regs['ptr']:
                print "  - Found a dereference at 0x{:08x}, tracking register {}".format(item, get_reg_str(inst.Op1))
                regs['ptr'].append(get_reg_str(inst.Op1))
                regs['nptr'].append(get_reg_str(inst.Op1))

        # If we've found an instruction that overwrites a tracked register, stop tracking it
        if inst.get_canon_mnem() in ["mov", "lea"] and inst.Op1 == o_reg:
            if get_reg_str(inst.Op1) in regs['ptr'] and get_reg_str(inst.Op1) not in regs['nptr']:
                print "  - Untracking pointer register {}: ".format(get_reg_str(inst.Op1) + disasm(item))
                regs['ptr'].remove(get_reg_str(inst.Op1))
            elif get_reg_str(inst.Op1) in regs['hndl'] and get_reg_str(inst.Op1) not in regs['nhndl']:
                print "  - Untracking handle register {}: ".format(get_reg_str(inst.Op1) + disasm(item))
                regs['hndl'].remove(get_reg_str(inst.Op1))

        # If we hit a call, just bail
        if inst.get_canon_mnem() == "call":
            break

        # If we're not tracking any registers, bail
        if len(regs['ptr']) == 0 and len(regs['hndl']) == 0:
            break


def rename_guids():
    labels = {}
    # Load GUIDs
    guids = dict((str(GUID(array=v)),k) for k, v in efiguids.GUIDs.iteritems())
    guids.update(dict((v,k) for k, v in local_guids.iteritems()))

    # Find all the data segments in this binary
    for seg_addr in idautils.Segments():
        seg = ida_segment.getseg(seg_addr)
        if seg.type == ida_segment.SEG_DATA:
            print "Processing data segment at 0x{:08x}".format(seg_addr)

            # Find any GUIDs we know about in the data segment
            cur_addr = seg.start_ea
            seg_end = seg.end_ea
            while cur_addr < seg_end:
                d = [ida_bytes.get_dword(cur_addr), ida_bytes.get_dword(cur_addr+0x4), ida_bytes.get_dword(cur_addr+0x8), ida_bytes.get_dword(cur_addr+0xC)]
                if (d[0] == 0 and d[1] == 0 and d[2] == 0 and d[3] == 0) or \
                    (d[0] == 0xFFFFFFFF and d[1] == 0xFFFFFFFF and d[2] == 0xFFFFFFFF and d[3] == 0xFFFFFFFF):
                     pass
                else:
                    guid = GUID(bytes=struct.pack("<LLLL", d[0], d[1], d[2], d[3]))
                    #print "Checking GUID {} at 0x{:08x}".format(str(guid), cur_addr)
                    gstr = str(guid)
                    if gstr in guids.keys():
                        print "  - Found GUID {} ({}) at 0x{:08x}".format(gstr, guids[gstr], cur_addr)
                        struct_label = underscore_to_global(guids[gstr])
                        if labels.get(struct_label) is None:
                            ida_name.set_name(cur_addr, struct_label)
                            labels[struct_label] = 1
                        else:
                            labels[struct_label] += 1
                            ida_name.set_name(cur_addr, "{}_{}".format(struct_label, labels[struct_label]))

                cur_addr += 0x08
        else:
            print "Skipping non-data segment at 0x{:08x}".format(seg_addr)


def update_protocols():
    pass


def update_protocol(guid_addr, protocol):
    pass
    # # Find xrefs to this GUID
    # xrefs = list(DataRefsTo(guid_addr))
    # print "Found %d xrefs to GUID %s" % (len(xrefs), str(guid_at_addr(guid_addr)))

    # # Process xrefs
    # for xref in xrefs:
    #     # We're only interested in xrefs in code where the left operand is a register, and the right operand is the
    #     # memory address of our GUID.
    #     if GetOpType(xref, 0) == o_reg and GetOpType(xref, 1) == o_mem and GetOperandValue(xref, 1) == struct_name:
    #         print "Processing xref from 0x%x: %s" % (xref, disasm(xref))
    #         update_struct_offsets_for_xref(xref, struct_name)
    #     else:
    #         print "Too hard basket - xref from 0x%x: %s" % (xref, disasm(xref))


def get_reg_str(operand):
    if operand.type == ida_ua.o_reg:
        # TODO: Find the operand length. Hardcoded to 8 for now.
        return ida_idp.get_reg_name(operand.reg, 8)
    return ''


def disasm(ea):
    return ida_lines.tag_remove(ida_lines.generate_disasm_line(ea))

def apply_struct_offset(inst, operand_no, struct_name):
    path_len = 1
    path = ida_pro.tid_array(path_len)
    path[0] = ida_struct.get_struc_id(struct_name)
    ida_bytes.op_stroff(inst, operand_no, path.cast(), path_len, 0)

def find_struct_refs():
    ida_bytes.is_stroff(ida_bytes.get_full_flags(ida_kernwin.get_screen_ea(), 0))


def guid_at_addr(guid_addr):
    return GUID(bytes=struct.pack("<LLLL", ida_bytes.get_dword(guid_addr), ida_bytes.get_dword(guid_addr + 0x4),
     ida_bytes.get_dword(guid_addr + 0x8), ida_bytes.get_dword(guid_addr + 0xC)))


def underscore_to_global(name):
    return 'g'+''.join(list(s.capitalize() for s in name.lower().split('_')))


def import_type(type_name):
    if ida_typeinf.import_type(ida_typeinf.get_idati(), 0, type_name) == 0xffffffffffffffff:
        return False
    return True


def get_op_str(ea, op_no):
    return ida_lines.tag_remove(ida_ua.print_operand(ea, op_no))

