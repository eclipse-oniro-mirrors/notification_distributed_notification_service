/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <thread>
#define private public

#include <fuzzer/FuzzedDataProvider.h>
#include "ans_permission_def.h"
#include "notification_analytics_util.h"
#include "notificationanalyticsutil_fuzzer.h"
#include "notification_request.h"
#include "notification_bundle_option.h"
#include "ans_status.h"

namespace OHOS {
namespace Notification {

    bool TestAnsStatus(FuzzedDataProvider *fdp)
    {
        int32_t errCode = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t sceneId = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        int32_t branchId = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        bool isPrint = fdp->ConsumeBool();
        std::string msg = fdp->ConsumeRandomLengthString();
        AnsStatus as(errCode, msg);
        AnsStatus as2(errCode, msg, sceneId, branchId);
        as.FormatSceneBranchStr(sceneId, branchId);
        as.AppendSceneBranch(sceneId, branchId, msg);
        as.InvalidParam(sceneId, branchId);
        as.InvalidParam(msg, sceneId, branchId);
        as.BuildMessage(isPrint);
        return true;
    }

    bool TestHaMetaMessage(FuzzedDataProvider *fdp)
    {
        HaMetaMessage message;
        bool flag = fdp->ConsumeBool();
        int32_t type = fdp->ConsumeIntegralInRange<int32_t>(0, 100);
        message.NeedReport();
        message.Checkfailed(flag);
        message.TypeCode(type);
        message.GetMessage();
        message.DeleteReason(type);
        OperationalMeta operMeta;
        nlohmann::json jsonObject;
        operMeta.ToJson(jsonObject);
        return true;
    }

    bool TestHaOperationMessage(FuzzedDataProvider *fdp)
    {
        bool flag = fdp->ConsumeBool();
        HaOperationMessage operationMessage = HaOperationMessage(false);
        std::string str1 = fdp->ConsumeRandomLengthString();
        std::string str2 = fdp->ConsumeRandomLengthString();
        std::string str3 = fdp->ConsumeRandomLengthString();
        std::vector<std::string> deviceTypes;
        deviceTypes.push_back(str1);
        deviceTypes.push_back(str2);
        deviceTypes.push_back(str3);
        operationMessage.KeyNode(true).SyncPublish("notification_1", deviceTypes);
        operationMessage.ToJson();
        operationMessage.ResetData();
        operationMessage.KeyNode(true).SyncDelete("notification_1");
        operationMessage = HaOperationMessage(true);
        deviceTypes.clear();
        deviceTypes.push_back("abc");
        deviceTypes.push_back("wearable");
        deviceTypes.push_back("headset");
        operationMessage.KeyNode(false).SyncPublish("notification_1", deviceTypes);
        operationMessage.ToJson();
        operationMessage.KeyNode(false).SyncDelete("notification_1");
        operationMessage.KeyNode(false).SyncDelete(str1, str2);
        operationMessage.notificationData.countTime = 0;
        operationMessage.SyncDelete(str1, std::string()).SyncClick(str1).SyncReply(str1);
        operationMessage.ResetData();
        operationMessage.liveViewData.countTime = 0;
        operationMessage = HaOperationMessage(true);
        operationMessage.ResetData();
        operationMessage.SyncDelete(str2, std::string()).SyncClick(str2).SyncReply(str2);

        operationMessage.ResetData();
        operationMessage.isLiveView_ = flag;
        operationMessage.DetermineWhetherToSend();
        operationMessage.liveViewData.keyNode++;
        operationMessage.DetermineWhetherToSend();
        operationMessage.liveViewData.countTime++;
        operationMessage.DetermineWhetherToSend();
        operationMessage.liveViewData.time = 0;
        operationMessage.DetermineWhetherToSend();
        operationMessage.ResetData();
        return true;
    }

    bool TestAnalyticsUtil(FuzzedDataProvider *fdp)
    {
        HaMetaMessage message;
        message.errorCode_ = ERR_OK;
        message.checkfailed_ = false;
        std::string bundle = fdp->ConsumeRandomLengthString();
        std::string bundle2 = fdp->ConsumeRandomLengthString();
        int32_t status = fdp->ConsumeIntegralInRange<int32_t>(0, 2);

        NotificationAnalyticsUtil::AddLiveViewSuccessNum(bundle, status);
        NotificationAnalyticsUtil::AddLiveViewFailedNum(bundle, status);
        NotificationAnalyticsUtil::AddLiveViewFailedNum(bundle2, status);
        NotificationAnalyticsUtil::AddLocalLiveViewFailedNum(bundle);
        NotificationAnalyticsUtil::AddLocalLiveViewFailedNum(bundle2);
        NotificationAnalyticsUtil::AddLocalLiveViewSuccessNum(bundle);
        NotificationAnalyticsUtil::AddLocalLiveViewSuccessNum(bundle2);
        return true;
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        TestAnsStatus(fdp);
        TestHaMetaMessage(fdp);
        TestHaOperationMessage(fdp);
        TestAnalyticsUtil(fdp);
        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    constexpr int sleepMs = 1000;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    return 0;
}