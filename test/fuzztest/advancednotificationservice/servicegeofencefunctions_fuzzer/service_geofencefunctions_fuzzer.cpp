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
#include "service_geofencefunctions_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#define private public
#define protected public
#include "advanced_notification_service.h"
#undef private
#undef protected
#include "ans_permission_def.h"
#include "mock_notification_request.h"
#include "notification_request.h"

namespace OHOS {
namespace Notification {
namespace {
    constexpr uint8_t TRIGGER_TYPE_SIZE = 1;
    constexpr uint8_t COORDINATE_SYSTEM_TYPE_SIZE = 2;
    constexpr uint8_t MONITOR_EVENT_SIZE = 2;
    constexpr uint8_t CONFIG_PATH_SIZE = 2;
    constexpr uint8_t SLOT_TYPE_SIZE = 10;
    constexpr uint8_t LIVE_VIEW_STATUS_SIZE = 6;
    constexpr uint32_t INTEGRAL_RANGE_SIZE = 100;
}

    std::shared_ptr<NotificationGeofence> GenerateGeofenceCondition(FuzzedDataProvider *fuzzData)
    {
        std::shared_ptr<NotificationGeofence> condition =
            std::make_shared<NotificationGeofence>();
        condition->SetLatitude(fuzzData->ConsumeFloatingPoint<double>());
        condition->SetLongitude(fuzzData->ConsumeFloatingPoint<double>());
        condition->SetRadius(fuzzData->ConsumeFloatingPoint<double>());
        condition->SetDelayTime(fuzzData->ConsumeIntegral<int32_t>());
        condition->SetCoordinateSystemType(static_cast<NotificationConstant::CoordinateSystemType>(
            fuzzData->ConsumeIntegralInRange<int32_t>(1, COORDINATE_SYSTEM_TYPE_SIZE)));
        condition->SetMonitorEvent(static_cast<NotificationConstant::MonitorEvent>(
            fuzzData->ConsumeIntegralInRange<int32_t>(1, MONITOR_EVENT_SIZE)));
        return condition;
    }

    std::shared_ptr<NotificationTrigger> GenerateNotificationTrigger(FuzzedDataProvider *fuzzData,
        const std::shared_ptr<NotificationGeofence> &condition)
    {
        std::shared_ptr<NotificationTrigger> trigger =
            std::make_shared<NotificationTrigger>();
        trigger->SetConfigPath(static_cast<NotificationConstant::ConfigPath>(
            fuzzData->ConsumeIntegralInRange<int32_t>(1, CONFIG_PATH_SIZE)));
        trigger->SetTriggerType(static_cast<NotificationConstant::TriggerType>(
            fuzzData->ConsumeIntegralInRange<int32_t>(1, TRIGGER_TYPE_SIZE)));
        trigger->SetGeofence(condition);
        trigger->SetDisplayTime(fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE));
        return trigger;
    }

    sptr<NotificationRequest> GenerateNotificationRequest(FuzzedDataProvider *fuzzData,
        const std::shared_ptr<NotificationTrigger> &trigger)
    {
        int32_t nid = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        sptr<NotificationRequest> request = new NotificationRequest(nid);
        std::string bundleName = fuzzData->ConsumeRandomLengthString();
        int32_t creatorUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        int32_t recvUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        int32_t uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        int32_t ownerId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
        request->SetOwnerBundleName(bundleName);
        request->SetCreatorUserId(creatorUserId);
        request->SetReceiverUserId(recvUserId);
        request->SetSlotType(slotType);
        request->SetOwnerUid(uid);
        request->SetOwnerUserId(ownerId);
        request->SetNotificationTrigger(trigger);
        auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
        auto content = std::make_shared<NotificationContent>(liveViewContent);
        request->SetContent(content);
        return request;
    }

    void CallParameterRelatedFunctions(FuzzedDataProvider *fuzzData,
        const std::shared_ptr<NotificationRecord> &record,
        const sptr<AdvancedNotificationService> &service)
    {
        AdvancedNotificationService::PublishNotificationParameter parameter;
        parameter.request = record->request;
        parameter.bundleOption = record->bundleOption;
        parameter.isUpdateByOwner = fuzzData->ConsumeBool();
        parameter.tokenCaller = fuzzData->ConsumeIntegral<uint32_t>();
        parameter.uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);

        service->OnNotifyDelayedNotification(parameter);
        service->UpdateTriggerNotification(parameter);
        auto value = fuzzData->ConsumeRandomLengthString();
        service->ParseGeofenceNotificationFromDb(value, parameter);
        service->SetTriggerNotificationRequestToDb(parameter);
        service->PublishPreparedNotificationInner(parameter);
        auto key = fuzzData->ConsumeRandomLengthString();
        std::shared_ptr<NotificationRecord> outRecord;
        service->GetDelayedNotificationParameterByTriggerKey(key, parameter, outRecord);
        service->OnNotifyDelayedNotificationInner(parameter, record);
    }

    void CallRecordRelatedFunctions(FuzzedDataProvider *fuzzData,
        const std::shared_ptr<NotificationRecord> &record,
        const sptr<AdvancedNotificationService> &service)
    {
        service->AddToTriggerNotificationList(record);
        service->ProcForDeleteGeofenceLiveView(record);
        service->UpdateTriggerRecord(record, record);
        service->TriggerNotificationRecordFilter(record);
    }

    void CallRequestRelatedFunctions(FuzzedDataProvider *fuzzData,
        const sptr<NotificationRequest> &request,
        const sptr<NotificationBundleOption> bundleOption,
        const sptr<AdvancedNotificationService> &service)
    {
        service->CheckGeofenceNotificationRequest(request, bundleOption);
        auto requestParam = request;
        service->UpdateTriggerRequest(requestParam);
        service->CheckTriggerNotificationRequest(request);
        service->CheckSwitchStatus(request, bundleOption);
        service->CheckGeofenceNotificationRequestLiveViewStatus(request);
        service->CheckLiveViewPendingCreateLiveViewStatus(request);
        service->CheckLiveViewPendingEndLiveViewStatus(request);
        service->IsGeofenceNotificationRequest(request);
        service->IsExistsGeofence(request);
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = AdvancedNotificationService::GetInstance();
        service->InitPublishProcess();
        service->CreateDialogManager();
        auto condition = GenerateGeofenceCondition(fuzzData);
        auto trigger = GenerateNotificationTrigger(fuzzData, condition);
        auto request = GenerateNotificationRequest(fuzzData, trigger);
        std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
        record->request = request;
        record->notification = new Notification(request);
        sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
        bundleOption->SetBundleName(fuzzData->ConsumeRandomLengthString());
        bundleOption->SetUid(fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE));
        record->bundleOption = bundleOption;

        auto userId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        service->ClearAllGeofenceNotificationRequests(userId);
        auto key = fuzzData->ConsumeRandomLengthString();
        std::vector<std::shared_ptr<NotificationRecord>> outRecords;
        service->FindGeofenceNotificationRecordByKey(key, outRecords);
        std::shared_ptr<NotificationRecord> outRecord;
        service->FindGeofenceNotificationRecordByTriggerKey(key, outRecord);
        service->FindNotificationRecordByKey(key, outRecord);
        service->RecoverGeofenceLiveViewFromDb(userId);
        service->RemoveTriggerNotificationListByTriggerKey(key);
        std::vector<AdvancedNotificationService::PublishNotificationParameter> parameters;
        service->GetBatchNotificationRequestsFromDb(parameters, userId);
        auto groupName = fuzzData->ConsumeRandomLengthString();
        service->ExecuteCancelGroupCancelFromTriggerNotificationList(bundleOption, groupName);
        NotificationKey notificationKey;
        auto nid = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        notificationKey.id = nid;
        auto label = fuzzData->ConsumeRandomLengthString();
        notificationKey.label = label;
        service->RemoveFromTriggerNotificationList(bundleOption, notificationKey);
        service->DeleteAllByUserStoppedFromTriggerNotificationList(key, userId);
        service->ExecuteRemoveNotificationFromTriggerNotificationList(bundleOption, nid, label);
        service->RemoveGroupByBundleFromTriggerNotificationList(bundleOption, groupName);
        AdvancedNotificationService::PublishNotificationParameter outParameter;
        auto isUpdateByOwner = fuzzData->ConsumeBool();
        service->GeneratePublishNotificationParameter(request, bundleOption, isUpdateByOwner, outParameter);
        CallParameterRelatedFunctions(fuzzData, record, service);
        CallRecordRelatedFunctions(fuzzData, record, service);
        CallRequestRelatedFunctions(fuzzData, request, bundleOption, service);
        service->SelfClean();
        return true;
    }

    void GenerateTriggerNotificationList(FuzzedDataProvider *fuzzData)
    {
        auto service = AdvancedNotificationService::GetInstance();
        for (int32_t i = 0; i < fuzzData->ConsumeIntegralInRange<int32_t>(1, INTEGRAL_RANGE_SIZE); ++i) {
            if (fuzzData->ConsumeBool()) {
                service->triggerNotificationList_.emplace_back(nullptr);
                continue;
            }
            auto record = std::make_shared<NotificationRecord>();
            service->triggerNotificationList_.push_back(record);
            if (fuzzData->ConsumeBool()) {
                record->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
                auto bundleName = fuzzData->ConsumeRandomLengthString();
                record->bundleOption->SetBundleName(bundleName);
                auto uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
                record->bundleOption->SetUid(uid);
            } else {
                record->bundleOption = nullptr;
            }

            if (fuzzData->ConsumeBool()) {
                record->request = sptr<NotificationRequest>::MakeSptr();
                auto creatorUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
                record->request->SetCreatorUserId(creatorUserId);
                auto notificationId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
                record->request->SetNotificationId(notificationId);
                auto label = fuzzData->ConsumeRandomLengthString();
                record->request->SetLabel(label);
                auto receiverUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
                record->request->SetReceiverUserId(receiverUserId);
                record->request->SetSlotType(static_cast<NotificationConstant::SlotType>(
                    fuzzData->ConsumeIntegralInRange<int32_t>(0, SLOT_TYPE_SIZE)));
                record->request->SetLiveViewStatus(
                    static_cast<NotificationLiveViewContent::LiveViewStatus>(
                    fuzzData->ConsumeIntegralInRange<int32_t>(0, LIVE_VIEW_STATUS_SIZE)));
            } else {
                record->request = nullptr;
            }

            if (fuzzData->ConsumeBool()) {
                auto key = fuzzData->ConsumeRandomLengthString();
                record->notification = sptr<Notification>::MakeSptr(record->request);
                record->notification->SetKey(key);
            } else {
                record->notification = nullptr;
            }
        }
    }

    bool DoSomethingInterestingWithMyAPISecond(FuzzedDataProvider *fuzzData)
    {
        auto service = AdvancedNotificationService::GetInstance();
        service->triggerNotificationList_.clear();
        GenerateTriggerNotificationList(fuzzData);
        service->RemoveAllNotificationsByBundleNameFromTriggerNotificationList(fuzzData->ConsumeRandomLengthString());
        service->RemoveFromTriggerNotificationList(fuzzData->ConsumeRandomLengthString());
        service->RemoveForDeleteAllFromTriggerNotificationList(fuzzData->ConsumeRandomLengthString(),
            fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE));
        service->CancelContinuousTaskNotificationFromTriggerNotificationList(fuzzData->ConsumeRandomLengthString(),
            fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE),
            fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE));
        AdvancedNotificationService::GetRecordParameter parameter{
            .notificationId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE),
            .uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE),
            .label = fuzzData->ConsumeRandomLengthString(),
            .bundleName = fuzzData->ConsumeRandomLengthString(),
            .userId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE)
        };
        service->GetRecordFromTriggerNotificationList(parameter);
        sptr<NotificationBundleOption> bundle;
        if (fuzzData->ConsumeBool()) {
            bundle = nullptr;
        } else {
            bundle = sptr<NotificationBundleOption>::MakeSptr();
            bundle->SetBundleName(fuzzData->ConsumeRandomLengthString());
            bundle->SetUid(fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE));
        }
        service->RemoveAllFromTriggerNotificationList(bundle);
        sptr<NotificationSlot> slot;
        if (fuzzData->ConsumeBool()) {
            slot = nullptr;
        } else {
            slot = sptr<NotificationSlot>::MakeSptr();
            slot->SetType(static_cast<NotificationConstant::SlotType>(
                fuzzData->ConsumeIntegralInRange<int32_t>(0, SLOT_TYPE_SIZE)));
        }
        service->RemoveNtfBySlotFromTriggerNotificationList(bundle, slot);
        service->triggerNotificationList_.clear();
        return true;
    }

    bool DoSomethingInterestingWithMyAPIThird(FuzzedDataProvider *fuzzData)
    {
        auto service = AdvancedNotificationService::GetInstance();
        service->triggerNotificationList_.clear();
        for (int32_t i = 0; i < fuzzData->ConsumeIntegralInRange<int32_t>(1, INTEGRAL_RANGE_SIZE); ++i) {
            auto record = std::make_shared<NotificationRecord>();
            service->triggerNotificationList_.push_back(record);
            record->bundleOption = sptr<NotificationBundleOption>::MakeSptr();
            auto bundleName = fuzzData->ConsumeRandomLengthString();
            record->bundleOption->SetBundleName(bundleName);
            auto uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
            record->bundleOption->SetUid(uid);
            record->request = sptr<NotificationRequest>::MakeSptr();
            auto creatorUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
            record->request->SetCreatorUserId(creatorUserId);
            auto notificationId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
            record->request->SetNotificationId(notificationId);
            auto groupName = fuzzData->ConsumeRandomLengthString();
            record->request->SetGroupName(groupName);
            auto receiverUserId = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
            record->request->SetReceiverUserId(receiverUserId);
            auto key = fuzzData->ConsumeRandomLengthString();
            record->notification = sptr<Notification>::MakeSptr(record->request);
            record->notification->SetKey(key);
        }

        service->DeleteAllByUserStoppedFromTriggerNotificationList(fuzzData->ConsumeRandomLengthString(),
            fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE));
        auto bundle = sptr<NotificationBundleOption>::MakeSptr();
        bundle->SetBundleName(fuzzData->ConsumeRandomLengthString());
        bundle->SetUid(fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE));
        service->ExecuteRemoveNotificationFromTriggerNotificationList(bundle,
            fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE),
            fuzzData->ConsumeRandomLengthString());
        service->RemoveGroupByBundleFromTriggerNotificationList(bundle,
            fuzzData->ConsumeRandomLengthString());
        service->triggerNotificationList_.clear();
        service->IsGeofenceNotificationRequest(nullptr);
        service->IsExistsGeofence(nullptr);
        auto request = sptr<NotificationRequest>::MakeSptr();
        if (fuzzData->ConsumeBool()) {
            request->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE);
            service->CheckSwitchStatus(request, nullptr);
        } else {
            request->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_END);
            service->CheckSwitchStatus(request, nullptr);
        }
        service->CheckGeofenceNotificationRequestLiveViewStatus(request);
        service->CheckTriggerNotificationRequest(request);
        service->CheckGeofenceNotificationRequest(nullptr, nullptr);
        return true;
    }

    bool DoSomethingInterestingWithMyAPIFourth(FuzzedDataProvider *fuzzData)
    {
        auto service = AdvancedNotificationService::GetInstance();
        auto request = sptr<NotificationRequest>::MakeSptr();
        request->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_PENDING_CREATE);
        auto notification = sptr<Notification>::MakeSptr(request);
        AdvancedNotificationService::PublishNotificationParameter parameter;
        parameter.request = request;
        parameter.bundleOption = sptr<NotificationBundleOption>::MakeSptr();
        parameter.isUpdateByOwner = fuzzData->ConsumeBool();
        parameter.tokenCaller = fuzzData->ConsumeIntegral<uint32_t>();
        parameter.uid = fuzzData->ConsumeIntegralInRange<int32_t>(0, INTEGRAL_RANGE_SIZE);
        service->UpdateTriggerNotification(parameter);

        auto condition = GenerateGeofenceCondition(fuzzData);
        auto trigger = GenerateNotificationTrigger(fuzzData, condition);
        auto request1 = GenerateNotificationRequest(fuzzData, trigger);
        std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
        record->request = request1;
        record->notification = sptr<Notification>::MakeSptr(request1);
        service->SetGeofenceTriggerTimer(record);
        service->CancelGeofenceTriggerTimer(record);
        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    MockRandomToken(&fdp, requestPermission);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    OHOS::Notification::DoSomethingInterestingWithMyAPISecond(&fdp);
    OHOS::Notification::DoSomethingInterestingWithMyAPIThird(&fdp);
    OHOS::Notification::DoSomethingInterestingWithMyAPIFourth(&fdp);
    constexpr int sleepMs = 1000;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    return 0;
}
