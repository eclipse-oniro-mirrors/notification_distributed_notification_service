/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#define private public
#include "notification_shell_command.h"
#undef private
#include "ans_inner_errors.h"
#include "ans_manager_interface.h"
#include "mock_ans_manager_stub.h"
#include "singleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

namespace {
static char g_dumpHelpMsg[] =
"request a option 'A' or 'R' or 'D'\n"
"usage: anm dump [<options>]\n"
"options list:\n"
"  --help, -h                   help menu\n"
"  --active,  -A                 list all active notifications\n"
"  --recent,  -R                 list recent notifications\n"
"  --bundle,  -b  <name>         dump the info filter by the specified bundle name\n"
"  --user-id, -u  <userId>       dump the info filter by the specified userId\n"
"  --receiver, -r  <userId>       dump the info filter by the specified receiver userId\n";

static char g_dumpActiveBound[] =
"error: option 'b' requires a value.\n"
"usage: anm dump [<options>]\noptions list:\n"
"  --help, -h                   help menu\n"
"  --active,  -A                 list all active notifications\n"
"  --recent,  -R                 list recent notifications\n"
"  --bundle,  -b  <name>         dump the info filter by the specified bundle name\n"
"  --user-id, -u  <userId>       dump the info filter by the specified userId\n"
"  --receiver, -r  <userId>       dump the info filter by the specified receiver userId\n";

static char g_dumpActiveUser[] =
"error: option 'u' requires a value.\n"
"usage: anm dump [<options>]\n"
"options list:\n"
"  --help, -h                   help menu\n"
"  --active,  -A                 list all active notifications\n"
"  --recent,  -R                 list recent notifications\n"
"  --bundle,  -b  <name>         dump the info filter by the specified bundle name\n"
"  --user-id, -u  <userId>       dump the info filter by the specified userId\n"
"  --receiver, -r  <userId>       dump the info filter by the specified receiver userId\n";

static char g_enableErrorInformation[] =
"error: option 'e' requires a value.\nusage: anm setting [<options>]\noptions list:\n"
"  --help, -h                   help menu\n"
"  --recent-count -c <number>   set the max count of recent notifications keeping in memory\n  --enable-notification"
" -e <bundleName:uid:enable> set notification enabled for the bundle, eg: -e com.example:10100:1\n  --set-device-status"
" -d <device:status> set device status, eg: -d device:1\n";

static char g_enableBundleNameNull[] =
"error: setting information error\n"
"usage: anm setting [<options>]\n"
"options list:\n  --help, -h                   help menu\n"
"  --recent-count -c <number>   set the max count of recent notifications keeping in memory\n  --enable-notification"
" -e <bundleName:uid:enable> set notification enabled for the bundle, eg: -e com.example:10100:1\n  --set-device-status"
" -d <device:status> set device status, eg: -d device:1\n";

static char g_enableObjectNull[] =
"error: object is null\n"
"error: object is null\n"
"usage: anm setting [<options>]\n"
"options list:\n  --help, -h                   help menu\n"
"  --recent-count -c <number>   set the max count of recent notifications keeping in memory\n  --enable-notification"
" -e <bundleName:uid:enable> set notification enabled for the bundle, eg: -e com.example:10100:1\n  --set-device-status"
" -d <device:status> set device status, eg: -d device:1\n";

static char g_unknownOption[] =
"error: unknown option.\n"
"usage: anm dump [<options>]\n"
"options list:\n"
"  --help, -h                   help menu\n"
"  --active,  -A                 list all active notifications\n"
"  --recent,  -R                 list recent notifications\n"
"  --bundle,  -b  <name>         dump the info filter by the specified bundle name\n"
"  --user-id, -u  <userId>       dump the info filter by the specified userId\n"
"  --receiver, -r  <userId>       dump the info filter by the specified receiver userId\n";

static char g_dumpActiveCount[] =
"error: option 'c' requires a value.\n"
"usage: anm setting [<options>]\n"
"options list:\n"
"  --help, -h                   help menu\n"
"  --recent-count -c <number>   set the max count of recent notifications keeping in memory\n  --enable-notification"
" -e <bundleName:uid:enable> set notification enabled for the bundle, eg: -e com.example:10100:1\n  --set-device-status"
" -d <device:status> set device status, eg: -d device:1\n";

static char g_helpMsg[] =
"error: unknown option.\n"
"usage: anm dump [<options>]\n"
"options list:\n"
"  --help, -h                   help menu\n"
"  --active,  -A                 list all active notifications\n"
"  --recent,  -R                 list recent notifications\n"
"  --bundle,  -b  <name>         dump the info filter by the specified bundle name\n"
"  --user-id, -u  <userId>       dump the info filter by the specified userId\n"
"  --receiver, -r  <userId>       dump the info filter by the specified receiver userId\n"
"usage: anm dump [<options>]\n"
"options list:\n"
"  --help, -h                   help menu\n"
"  --active,  -A                 list all active notifications\n"
"  --recent,  -R                 list recent notifications\n"
"  --bundle,  -b  <name>         dump the info filter by the specified bundle name\n"
"  --user-id, -u  <userId>       dump the info filter by the specified userId\n"
"  --receiver, -r  <userId>       dump the info filter by the specified receiver userId\n";

class AnmManagerDumpTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    void MakeMockObjects();

    std::string cmd_ = "dump";
    std::string enable_ = "setting";
    std::string toolName_ = "anm";
    sptr<AnsManagerInterface> proxyPtr_;
    sptr<MockAnsManagerStub> stubPtr_;
};

void AnmManagerDumpTest::SetUpTestCase()
{}

void AnmManagerDumpTest::TearDownTestCase()
{}

void AnmManagerDumpTest::SetUp()
{
    // reset optind to 0
    optind = 0;

    // make mock objects
    MakeMockObjects();
}

void AnmManagerDumpTest::TearDown()
{}

void AnmManagerDumpTest::MakeMockObjects()
{
    // mock a stub
    stubPtr_ = new (std::nothrow) MockAnsManagerStub();

    // mock a proxy
    proxyPtr_ = iface_cast<AnsManagerInterface>(stubPtr_);

    // set the mock proxy
    auto ansNotificationPtr = DelayedSingleton<AnsNotification>::GetInstance();
}

/**
 * @tc.number: Anm_Command_Dump_0100
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -h" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_0100, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-h",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), g_dumpHelpMsg);
}

/**
 * @tc.number: Anm_Command_Dump_0200
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -A" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_0200, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-A",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    cmd.ExecCommand();
 
    EXPECT_EQ(stubPtr_->GetCmd(), "");
}

/**
 * @tc.number: Anm_Command_Dump_0300
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -R" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_0300, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-R",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    cmd.ExecCommand();

    EXPECT_EQ(stubPtr_->GetCmd(), "");
}

/**
 * @tc.number: Anm_Command_Dump_0400
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -R -b" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_0400, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-R",
        (char *)"-b",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), g_dumpActiveBound);
}

/**
 * @tc.number: Anm_Command_Dump_0500
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -A -b example" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_0500, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-A",
        (char *)"-b",
        (char *)"example",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    cmd.ExecCommand();

    EXPECT_EQ(stubPtr_->GetCmd(), "");
    EXPECT_EQ(stubPtr_->GetBundle(), "");
}

/**
 * @tc.number: Anm_Command_Dump_0600
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -A -b" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_0600, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-A",
        (char *)"-b",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), g_dumpActiveBound);
}

/**
 * @tc.number: Anm_Command_Dump_0700
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -R -b example" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_0700, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-R",
        (char *)"-b",
        (char *)"example",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    cmd.ExecCommand();

    EXPECT_EQ(stubPtr_->GetCmd(), "");
    EXPECT_EQ(stubPtr_->GetBundle(), "");
}

/**
 * @tc.number: Anm_Command_Dump_0800
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -R -u" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_0800, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-R",
        (char *)"-u",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), g_dumpActiveUser);
}

/**
 * @tc.number: Anm_Command_Dump_0900
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -A -u" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_0900, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-A",
        (char *)"-u",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), g_dumpActiveUser);
}

/**
 * @tc.number: Anm_Command_Dump_1000
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -A -u 33" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_1000, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-A",
        (char *)"-u",
        (char *)"33",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    cmd.ExecCommand();

    EXPECT_EQ(stubPtr_->GetCmd(), "");
    EXPECT_EQ(stubPtr_->GetUserId(), 0);
}

/**
 * @tc.number: Anm_Command_Dump_1100
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -R -u 33" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_1100, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-R",
        (char *)"-u",
        (char *)"33",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    cmd.ExecCommand();

    EXPECT_EQ(stubPtr_->GetCmd(), "");
    EXPECT_EQ(stubPtr_->GetUserId(), 0);
}

/**
 * @tc.number: Anm_Command_Dump_1200
 * @tc.name: RunAsSettingCommand
 * @tc.desc: test RunAsSettingCommand function
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_1200, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-h",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.RunAsSettingCommand(), ERR_INVALID_VALUE);
}

/**
 * @tc.number: Anm_Command_Dump_1300
 * @tc.name: RunSetEnableCmd
 * @tc.desc: test RunSetEnableCmd function
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_1300, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-h",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.RunSetEnableCmd(), ERR_ANS_SERVICE_NOT_CONNECTED);
}

/**
 * @tc.number: Anm_Command_Dump_1400
 * @tc.name: GetCommandErrorMsg
 * @tc.desc: test GetCommandErrorMsg function
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_1400, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-h",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.GetCommandErrorMsg(), "anm_dump: 'dump' is not a valid anm_dump command. See 'anm_dump help'.\n");
}

/**
 * @tc.number: Anm_Command_Dump_1500
 * @tc.name: GetUnknownOptionMsg
 * @tc.desc: test GetUnknownOptionMsg function
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_1500, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-h",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    std::string unknownOption = "aa";

    EXPECT_EQ(cmd.GetUnknownOptionMsg(unknownOption), "error: unknown option.\n");
}

/**
 * @tc.number: Anm_Command_Dump_1600
 * @tc.name: GetMessageFromCode
 * @tc.desc: test GetMessageFromCode function
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_1600, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-h",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    int32_t code = 11;

    EXPECT_EQ(cmd.GetMessageFromCode(code), "");
}

/**
 * @tc.number: Anm_Command_Dump_1700
 * @tc.name: RunAsSettingCommand
 * @tc.desc: Verify the "anm setting -e bundleName:uid:enable" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_1700, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)enable_.c_str(),
        (char *)"-e",
        (char *)"dd:ss:aa",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "set notification enabled failed\n");
}

/**
 * @tc.number: Anm_Command_Dump_1800
 * @tc.name: RunAsSettingCommand
 * @tc.desc: Verify the "anm setting -e" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_1800, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)enable_.c_str(),
        (char *)"-e",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), g_enableErrorInformation);
}

/**
 * @tc.number: Anm_Command_Dump_1900
 * @tc.name: RunAsSettingCommand
 * @tc.desc: Verify the "anm setting -e bundleName:uid" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_1900, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)enable_.c_str(),
        (char *)"-e",
        (char *)"dd:ss",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), g_enableBundleNameNull);
}

/**
 * @tc.number: Anm_Command_Dump_2000
 * @tc.name: RunAsSettingCommand
 * @tc.desc: Verify the "anm setting -e bundleName:uid:enable" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_2000, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)enable_.c_str(),
        (char *)"-e",
        (char *)"22",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.RunSetEnableCmd(), cmd.RunAsSettingCommand());
    EXPECT_EQ(cmd.ExecCommand(), g_enableObjectNull);
}

/**
 * @tc.number: Anm_Command_Dump_2100
 * @tc.name: RunAsSettingCommand
 * @tc.desc: Verify the "anm setting -e bundleName:uid:enable" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_2100, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)enable_.c_str(),
        (char *)"-e",
        (char *)"gg:ss:aa",
        (char *)"22",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), "set notification enabled success\n");
}

/**
 * @tc.number: Anm_Command_Dump_2200
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -A -s" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_2200, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-A",
        (char *)"-s",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), g_unknownOption);
}

/**
 * @tc.number: Anm_Command_Dump_2300
 * @tc.name: RunAsSettingCommand
 * @tc.desc: Verify the "anm setting -e" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_2300, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)enable_.c_str(),
        (char *)"-c",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    EXPECT_EQ(cmd.ExecCommand(), g_dumpActiveCount);
}

/**
 * @tc.number: Anm_Command_Dump_2400
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -D" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_0240, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-D",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    cmd.ExecCommand();
 
    EXPECT_EQ(cmd.ExecCommand(), g_helpMsg);
}

/**
 * @tc.number: Anm_Command_Dump_2500
 * @tc.name: ExecCommand
 * @tc.desc: Verify the "anm dump -D" command.
 */
HWTEST_F(AnmManagerDumpTest, Anm_Notification_Shell_Dump_0250, Function | MediumTest | Level1)
{
    char *argv[] = {
        (char *)toolName_.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-p",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    NotificationShellCommand cmd(argc, argv);

    cmd.ExecCommand();
 
    EXPECT_EQ(cmd.ExecCommand(), g_helpMsg);
}
}  // namespace