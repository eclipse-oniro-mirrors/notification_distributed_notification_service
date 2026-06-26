/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "shell_command.h"

#include <getopt.h>
#include "ans_log_wrapper.h"
#include "command_output.h"

namespace OHOS {
namespace Notification {
ShellCommand::ShellCommand(int argc, char *argv[], std::string name)
{
    opterr = 0;
    argc_ = argc;
    argv_ = argv;
    name_ = name;
    if (argc < MIN_ARGUMENT_NUMBER || argc > MAX_ARGUMENT_NUMBER) {
        cmd_ = "help";
        return;
    }
    cmd_ = argv[1];
    if (cmd_ == "--help" || cmd_ == "-h") {
        cmd_ = "help";
    }
    for (int i = 2; i < argc; i++) {
        argList_.push_back(argv[i]);
        resultReceiver_.append(argv_[i]).append("|");
    }
}

ShellCommand::~ShellCommand()
{}

ErrCode ShellCommand::OnCommand()
{
    int32_t result = OHOS::ERR_OK;
    auto respond = commandMap_[cmd_];
    if (respond == nullptr) {
        std::string errorMsg = GetCommandErrorMsg();
        resultReceiver_ = errorMsg;
        return OHOS::ERR_INVALID_VALUE;
    }
    if (Init() == OHOS::ERR_OK) {
        ANS_LOGD("Init is ERR_OK.");
        respond();
    } else {
        OutputError("ERR_INIT_FAILED", "初始化失败: 无法连接通知服务",
            "请检查通知服务是否正在运行。示例: 确认 AdvancedNotificationService 已启动", resultReceiver_);
        result = OHOS::ERR_INVALID_VALUE;
    }
    return result;
}

std::string ShellCommand::ExecCommand()
{
    int32_t result = CreateCommandMap();
    if (result != OHOS::ERR_OK) {
        ANS_LOGE("failed to create command map.\n");
    }
    result = OnCommand();
    if (result != OHOS::ERR_OK) {
        ANS_LOGE("failed to execute your command.\n");
    }
    return resultReceiver_;
}

std::string ShellCommand::GetCommandErrorMsg() const
{
    std::string output;
    OutputError("ERR_UNKNOWN_COMMAND", "未知命令: " + cmd_,
        "请使用有效命令。可用命令: help, publish, cancel, remove, enable, slotflags, list。"
        "示例: ohos-notificationManager help", output);
    return output;
}

std::string ShellCommand::GetUnknownOptionMsg(std::string &unknownOption) const
{
    std::string output;
    OutputError("ERR_UNKNOWN_OPTION", "未知选项: 不支持的命令选项",
        "请使用 --help 查看可用选项", output);
    return output;
}

std::string ShellCommand::GetMessageFromCode(const int32_t code) const
{
    ANS_LOGD("[%{public}s(%{public}s)] enter", __FILE__, __FUNCTION__);
    ANS_LOGD("code = %{public}d", code);
    std::string result = "";
    if (messageMap_.find(code) != messageMap_.end()) {
        std::string message = messageMap_.at(code);
        if (message.size() != 0) {
            result.append(message + "\n");
        }
    }
    ANS_LOGD("result = %{public}s", result.c_str());
    return result;
}
}  // namespace Notification
}  // namespace OHOS
