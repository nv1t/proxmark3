//-----------------------------------------------------------------------------
// Copyright (C) 2012 nuit
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE DESfire commands
//-----------------------------------------------------------------------------

#include "cmdhfdes.h"
#include "proxmark3.h"

static int CmdHelp(const char *Cmd);

int CmdHFDEStest(const char *Cmd)
{
    printf("Command Test\n");
    return 0;
}

int CmdHFDESReader(const char *Cmd)
{
    uint32_t uid = 0;
    uint32_t nt = 0;
    uint64_t par_list = 0, ks_list = 0, r_key = 0;
    uint8_t isOK = 0;
    uint8_t keyBlock[8] = {0};
    UsbCommand c  ={CMD_MIFARE_DES_READER, {3, 0x60, 0}};
    SendCommand(&c);

    UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 2000);

    if (resp != NULL) {
        uint8_t isOk  = resp->arg[0] & 0xff;

        PrintAndLog("isOk:%02x", isOk);
    } else {
        PrintAndLog("Command execute timeout");
    }

    return 0;
}  

int CmdHFDESDbg(const char *Cmd)
{
    int dbgMode = param_get32ex(Cmd, 0, 0, 10);
    if (dbgMode > 4) {
        PrintAndLog("Max debud mode parameter is 4 \n");
    }

    if (strlen(Cmd) < 1 || !param_getchar(Cmd, 0) || dbgMode > 4) {
        PrintAndLog("Usage:  hf des dbg  <debug level>");
        PrintAndLog(" 0 - no debug messages");
        PrintAndLog(" 1 - error messages");
        PrintAndLog(" 2 - all messages");
        PrintAndLog(" 4 - extended debug mode");
        return 0;
    }

  UsbCommand c = {CMD_MIFARE_SET_DBGMODE, {dbgMode, 0, 0}};
  SendCommand(&c);

  return 0;
}



static command_t CommandTable[] = 
{
    {"help",    CmdHelp,    1,  "This help"},
    {"dbg",     CmdHFDESDbg, 0, "Set default debug mode"},
    {"reader",  CmdHFDESReader, 0, "Reader"}, 
    {"test",    CmdHFDEStest,   0,  "test"},
    {NULL, NULL, 0, NULL}
};

int CmdHFDES(const char *Cmd)
{
    //flush
    while (WaitForResponseTimeout(CMD_ACK,500) != NULL);
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd)
{
    CmdsHelp(CommandTable);
    return 0;
}
