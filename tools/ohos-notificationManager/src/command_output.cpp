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

#include "command_output.h"

namespace OHOS {
namespace Notification {
namespace {
std::string ExternalCodeToErrCodeString(int32_t externalCode)
{
    switch (externalCode) {
        case ERROR_PERMISSION_DENIED:
            return "ERR_PERMISSION_DENIED";
        case ERROR_NOT_SYSTEM_APP:
            return "ERR_NOT_SYSTEM_APP";
        case ERROR_PARAM_INVALID:
            return "ERR_PARAM_INVALID";
        case ERROR_INTERNAL_ERROR:
            return "ERR_INTERNAL_ERROR";
        case ERROR_IPC_ERROR:
            return "ERR_IPC_ERROR";
        case ERROR_SERVICE_CONNECT_ERROR:
            return "ERR_SERVICE_CONNECT_ERROR";
        case ERROR_NOTIFICATION_CLOSED:
            return "ERR_NOTIFICATION_CLOSED";
        case ERROR_SLOT_CLOSED:
            return "ERR_SLOT_CLOSED";
        case ERROR_NOTIFICATION_UNREMOVABLE:
            return "ERR_NOTIFICATION_UNREMOVABLE";
        case ERROR_NOTIFICATION_NOT_EXIST:
            return "ERR_NOTIFICATION_NOT_EXIST";
        case ERROR_USER_NOT_EXIST:
            return "ERR_USER_NOT_EXIST";
        case ERROR_OVER_MAX_NUM_PER_SECOND:
            return "ERR_OVER_MAX_NUM_PER_SECOND";
        case ERROR_DISTRIBUTED_OPERATION_FAILED:
            return "ERR_DISTRIBUTED_OPERATION_FAILED";
        case ERROR_READ_TEMPLATE_CONFIG_FAILED:
            return "ERR_READ_TEMPLATE_CONFIG_FAILED";
        case ERROR_NO_MEMORY:
            return "ERR_NO_MEMORY";
        case ERROR_DIALOG_IS_POPPING:
            return "ERR_DIALOG_IS_POPPING";
        case ERROR_NO_RIGHT:
            return "ERR_NO_RIGHT";
        case ERROR_REPEAT_SET:
            return "ERR_REPEAT_SET";
        case ERROR_EXPIRED_NOTIFICATION:
            return "ERR_EXPIRED_NOTIFICATION";
        case ERROR_NO_AGENT_SETTING:
            return "ERR_NO_AGENT_SETTING";
        case ERROR_SETTING_WINDOW_EXIST:
            return "ERR_SETTING_WINDOW_EXIST";
        case ERROR_NO_PROFILE_TEMPLATE:
            return "ERR_NO_PROFILE_TEMPLATE";
        case ERROR_REJECTED_WITH_DISABLE_NOTIFICATION:
            return "ERR_REJECTED_WITH_DISABLE_NOTIFICATION";
        case ERROR_DISTRIBUTED_OPERATION_TIMEOUT:
            return "ERR_DISTRIBUTED_OPERATION_TIMEOUT";
        case ERROR_BUNDLE_INVALID:
            return "ERR_BUNDLE_INVALID";
        case ERROR_NOT_IMPL_EXTENSIONABILITY:
            return "ERR_NOT_IMPL_EXTENSIONABILITY";
        case ERROR_NO_CUSTOM_RINGTONE_INFO:
            return "ERR_NO_CUSTOM_RINGTONE_INFO";
        case ERROR_GEOFENCE_ENABLED:
            return "ERR_GEOFENCE_ENABLED";
        case ERROR_LOCATION_CLOSED:
            return "ERR_LOCATION_CLOSED";
        case ERROR_AWARNESS_SUGGESTIONS_CLOSED:
            return "ERR_AWARNESS_SUGGESTIONS_CLOSED";
        case ERR_NOTIFICATION_NOT_SUPPORT:
            return "ERR_NOTIFICATION_NOT_SUPPORT";
        case ERROR_NETWORK_UNREACHABLE:
            return "ERR_NETWORK_UNREACHABLE";
        case ERROR_BUNDLE_NOT_FOUND:
            return "ERR_BUNDLE_NOT_FOUND";
        default:
            return "ERR_INTERNAL_ERROR";
    }
}

std::string BuildErrMsg(const std::string& action, int32_t externalCode, const std::string& errMessage)
{
    return action + "失败: [" + std::to_string(externalCode) + "] " + errMessage;
}

std::string BuildSuggestion(int32_t externalCode, const std::string& exampleCmd)
{
    switch (externalCode) {
        case ERROR_PERMISSION_DENIED:
            return "请确认调用者拥有所需权限。参考: ohos.permission.NOTIFICATION_CONTROLLER 或 "
                   "ohos.permission.NOTIFICATION_AGENT_CONTROLLER";
        case ERROR_NOT_SYSTEM_APP:
            return "此接口仅限系统应用调用，请确认调用者身份";
        case ERROR_PARAM_INVALID:
            return "请检查输入参数是否有效。" + exampleCmd;
        case ERROR_SERVICE_CONNECT_ERROR:
            return "请检查通知服务是否正在运行。确认 AdvancedNotificationService 已启动";
        case ERROR_NOTIFICATION_CLOSED:
            return "目标应用的通知功能已关闭，请先通过 enableNotification 开启通知权限";
        case ERROR_SLOT_CLOSED:
            return "目标通知渠道已关闭，请检查渠道设置";
        case ERROR_NOTIFICATION_UNREMOVABLE:
            return "该通知不可删除（已标记为unRemovable），无法取消";
        case ERROR_NOTIFICATION_NOT_EXIST:
            return "指定通知不存在，请确认通知ID和bundleOption是否匹配已发布的通知。" + exampleCmd;
        case ERROR_BUNDLE_NOT_FOUND:
            return "指定bundle不存在，请确认bundleName和uid是否正确。" + exampleCmd;
        case ERROR_BUNDLE_INVALID:
            return "指定bundle无效，请确认bundleName和uid参数。" + exampleCmd;
        case ERROR_OVER_MAX_NUM_PER_SECOND:
            return "通知发送频率已达上限，请降低发送频率后重试";
        case ERROR_IPC_ERROR:
            return "IPC通信异常，请重试或检查系统服务状态";
        case ERROR_NO_RIGHT:
            return "无操作权限，请确认推送配置或订阅状态。" + exampleCmd;
        case ERROR_NO_MEMORY:
            return "系统内存不足，请稍后重试";
        case ERROR_INTERNAL_ERROR:
            return "内部错误，请重试或检查通知服务状态。" + exampleCmd;
        default:
            return "请检查参数和服务状态。" + exampleCmd;
    }
}
}

void OutputSuccess(const nlohmann::json& data, std::string& output)
{
    nlohmann::json response;
    response["type"] = "result";
    response["status"] = "success";
    response["data"] = data;
    output = response.dump();
}

void OutputError(const std::string& errCode, const std::string& errMsg,
    const std::string& suggestion, std::string& output)
{
    nlohmann::json response;
    response["type"] = "result";
    response["status"] = "failed";
    response["errCode"] = errCode;
    response["errMsg"] = errMsg;
    response["suggestion"] = suggestion;
    output = response.dump();
}

void OutputApiError(ErrCode internalErrCode, const std::string& action,
    const std::string& exampleCmd, std::string& output)
{
    int32_t externalCode = InnerErrorToExternal(internalErrCode);
    std::string errCodeStr = ExternalCodeToErrCodeString(externalCode);
    std::string errMessage = GetExternalErrMessage(externalCode, "Unknown error");
    std::string errMsg = BuildErrMsg(action, externalCode, errMessage);
    std::string suggestion = BuildSuggestion(externalCode, exampleCmd);
    OutputError(errCodeStr, errMsg, suggestion, output);
}
}  // namespace Notification
}  // namespace OHOS
