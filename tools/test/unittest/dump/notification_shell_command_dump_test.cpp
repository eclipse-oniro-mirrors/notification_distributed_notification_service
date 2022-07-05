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
#include "ans_manager_interface.h"
#include "mock_ans_manager_stub.h"
#include "singleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

namespace {
    static char DUMP_HELP_MSG[] =
    "request a option 'A' or 'R' or 'D'\n"
    "usage: anm dump [<options>]\n"
    "options list:\n"
    "  --help, -h                   help menu\n"
    "  --active,  -A                 list all active notifications\n"
    "  --recent,  -R                 list recent notifications\n"
    "  --bundle,  -b  <name>         dump the info filter by the specified bundle name\n"
    "  --user-id, -u  <userId>       dump the info filter by the specified userId\n";

    static char DUMP_ACTIVE_BOUND[] =
    "error: option 'b' requires a value.\n"
    "usage: anm dump [<options>]\noptions list:\n"
    "  --help, -h                   help menu\n"
    "  --active,  -A                 list all active notifications\n"
    "  --recent,  -R                 list recent notifications\n"
    "  --bundle,  -b  <name>         dump the info filter by the specified bundle name\n"
    "  --user-id, -u  <userId>       dump the info filter by the specified userId\n";

    static char DUMP_ACTIVE_USER[] =
    "error: option 'u' requires a value.\n"
    "usage: anm dump [<options>]\n"
    "options list:\n"
    "  --help, -h                   help menu\n"
    "  --active,  -A                 list all active notifications\n"
    "  --recent,  -R                 list recent notifications\n"
    "  --bundle,  -b  <name>         dump the info filter by the specified bundle name\n"
    "  --user-id, -u  <userId>       dump the info filter by the specified userId\n";

    static char BUNDLE_NAME[] = "example";
    static char COMMAND_ACTIVE[] = "active";
    static char COMMAND_RECENT[] = "recent";
}

class AnmManagerDumpTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    void MakeMockObjects();

    std::string cmd_ = "dump";
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
    ansNotificationPtr->ansManagerProxy_ = proxyPtr_;
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

    EXPECT_EQ(cmd.ExecCommand(), DUMP_HELP_MSG);
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
 
    EXPECT_EQ(stubPtr_->GetCmd(), COMMAND_ACTIVE);
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

    EXPECT_EQ(stubPtr_->GetCmd(), COMMAND_RECENT);
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

    EXPECT_EQ(cmd.ExecCommand(), DUMP_ACTIVE_BOUND);
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

    EXPECT_EQ(stubPtr_->GetCmd(), COMMAND_ACTIVE);
    EXPECT_EQ(stubPtr_->GetBundle(), BUNDLE_NAME);
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

    EXPECT_EQ(cmd.ExecCommand(), DUMP_ACTIVE_BOUND);
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

    EXPECT_EQ(stubPtr_->GetCmd(), COMMAND_RECENT);
    EXPECT_EQ(stubPtr_->GetBundle(), BUNDLE_NAME);
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

    EXPECT_EQ(cmd.ExecCommand(), DUMP_ACTIVE_USER);
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

    EXPECT_EQ(cmd.ExecCommand(), DUMP_ACTIVE_USER);
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

    EXPECT_EQ(stubPtr_->GetCmd(), COMMAND_ACTIVE);
    EXPECT_EQ(stubPtr_->GetUserId(), 33);
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

    EXPECT_EQ(stubPtr_->GetCmd(), COMMAND_RECENT);
    EXPECT_EQ(stubPtr_->GetUserId(), 33);
}

