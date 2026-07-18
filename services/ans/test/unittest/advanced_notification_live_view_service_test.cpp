/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <chrono>
#include <functional>
#include <memory>
#include <thread>

#include "gtest/gtest.h"

#define private public
#include "advanced_notification_service.h"
#include "advanced_notification_inline.h"
#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "ans_log_wrapper.h"
#include "ans_result_data_synchronizer.h"
#include "accesstoken_kit.h"
#include "notification_preferences.h"
#include "notification_constant.h"
#include "pixel_map.h"
#include "int_wrapper.h"
#include "notification_live_view_content.h"
#include "notification_request.h"
#include "notification_app_state_observer.h"
#include "notification_content.h"
#include "notification_record.h"
#include "want_params_wrapper.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::Media;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace Notification {
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);

class AnsLiveViewServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp();
    void TearDown();
    std::shared_ptr<PixelMap> MakePixelMap(int32_t width, int32_t height);

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AnsLiveViewServiceTest::advancedNotificationService_ = nullptr;

constexpr int32_t TEAR_DOWN_SLEEP_MS = 500;

std::shared_ptr<PixelMap> AnsLiveViewServiceTest::MakePixelMap(int32_t width, int32_t height)
{
    const int32_t PIXEL_BYTES = 4;
    std::shared_ptr<PixelMap> pixelMap = std::make_shared<PixelMap>();
    if (pixelMap == nullptr) {
        return pixelMap;
    }
    ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = PixelFormat::ARGB_8888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap->SetImageInfo(info);
    int32_t rowDataSize = width * PIXEL_BYTES;
    uint32_t bufferSize = rowDataSize * height;
    void *buffer = malloc(bufferSize);
    if (buffer != nullptr) {
        pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    }
    EXPECT_NE(buffer, nullptr);
    return pixelMap;
}

void AnsLiveViewServiceTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->CancelAll("",
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
    }
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AnsLiveViewServiceTest::TearDown()
{
    if (advancedNotificationService_ != nullptr) {
        std::this_thread::sleep_for(std::chrono::milliseconds(TEAR_DOWN_SLEEP_MS));
    }
    delete advancedNotificationService_;
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

inline void SleepForFC()
{
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

inline int32_t GetFailCountFromDb(int32_t userId)
{
    std::string value;
    NotificationPreferences::GetInstance()->GetKvFromDb("ans_recover_fail_count", value, userId);
    if (value.empty()) {
        return 0;
    }
    return atoi(value.c_str());
}

inline void SetFailCountToDb(int32_t userId, int32_t count)
{
    NotificationPreferences::GetInstance()->SetKvToDb("ans_recover_fail_count", std::to_string(count), userId);
}

/**
 * @tc.name: ProcForDeleteLiveView_00001
 * @tc.desc: Test ProcForDeleteLiveView
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, ProcForDeleteLiveView_00001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);

    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    AdvancedNotificationService::NotificationRequestDb requestDb =
        { .request = record->request, .bundleOption = bundle};
    auto ret = advancedNotificationService_->SetNotificationRequestToDb(requestDb);
    ASSERT_EQ(ret, (int)ERR_OK);

    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    ret = advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb);
    ASSERT_EQ(requestsdb.size(), 1);

    advancedNotificationService_->ProcForDeleteLiveView(record);
    requestsdb.clear();
    ret = advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb);
    ASSERT_EQ(requestsdb.size(), 0);
}

/**
 * @tc.name: SetNotificationRequestToDb_00001
 * @tc.desc: Test SetNotificationRequestToDb
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, SetNotificationRequestToDb_00001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetAutoDeletedTime(NotificationConstant::NO_DELAY_DELETE_TIME);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);

    AdvancedNotificationService::NotificationRequestDb requestDb =
        { .request = request, .bundleOption = bundle};
    auto ret = advancedNotificationService_->SetNotificationRequestToDb(requestDb);
    ASSERT_EQ(ret, (int)ERR_OK);

    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    ret = advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb);
    ASSERT_EQ(requestsdb.size(), 0);
}

/**
 * @tc.name: SetNotificationRequestToDb_00002
 * @tc.desc: Test SetNotificationRequestToDb
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, SetNotificationRequestToDb_00002, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetReceiverUserId(100);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    auto bundle = new NotificationBundleOption("test", 1);
    AdvancedNotificationService::NotificationRequestDb requestDb =
        { .request = request, .bundleOption = bundle};
    auto ret = advancedNotificationService_->SetNotificationRequestToDb(requestDb);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: FillLockScreenPicture_00001
 * @tc.desc: Test FillLockScreenPicture
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, FillLockScreenPicture_00001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> newRequest = new (std::nothrow) NotificationRequest();
    newRequest->SetSlotType(slotType);
    newRequest->SetNotificationId(1);
    auto newLiveContent = std::make_shared<NotificationLiveViewContent>();
    auto newContent = std::make_shared<NotificationContent>(newLiveContent);
    newRequest->SetContent(newContent);

    sptr<NotificationRequest> oldRequest = new (std::nothrow) NotificationRequest();
    oldRequest->SetSlotType(slotType);
    oldRequest->SetNotificationId(1);
    auto oldLiveContent = std::make_shared<NotificationLiveViewContent>();
    auto oldContent = std::make_shared<NotificationContent>(oldLiveContent);

    std::shared_ptr<PixelMap> pixelMap = MakePixelMap(1, 1);
    oldLiveContent->SetLockScreenPicture(pixelMap);
    oldRequest->SetContent(oldContent);

    advancedNotificationService_->FillLockScreenPicture(newRequest, oldRequest);
    EXPECT_NE(newRequest->GetContent()->GetNotificationContent()->GetLockScreenPicture(), nullptr);
}

/**
 * @tc.name: SetLockScreenPictureToDb_001
 * @tc.desc: Test SetLockScreenPictureToDb
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, SetLockScreenPictureToDb_001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetAutoDeletedTime(NotificationConstant::NO_DELAY_DELETE_TIME);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    std::shared_ptr<PixelMap> pixelMap = MakePixelMap(1024, 1);
    liveContent->SetLockScreenPicture(pixelMap);
    request->SetContent(content);

    auto ret = advancedNotificationService_->SetLockScreenPictureToDb(request);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: IsSaCreateSystemLiveViewAsBundle_001
 * @tc.desc: Test IsSaCreateSystemLiveViewAsBundle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, IsSaCreateSystemLiveViewAsBundle_001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    int creatorUid = 1;
    request->SetCreatorUid(creatorUid);
    int ownerUid = 2;
    request->SetOwnerUid(ownerUid);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", creatorUid);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    bool flag = advancedNotificationService_->IsSaCreateSystemLiveViewAsBundle(record, creatorUid);
    ASSERT_EQ(flag, true);
}

/**
 * @tc.name: IsSaCreateSystemLiveViewAsBundle_002
 * @tc.desc: Test IsSaCreateSystemLiveViewAsBundle return false
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, IsSaCreateSystemLiveViewAsBundle_002, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    int creatorUid = 1;
    request->SetCreatorUid(creatorUid);
    int ownerUid = 2;
    request->SetOwnerUid(ownerUid);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    bool flag = advancedNotificationService_->IsSaCreateSystemLiveViewAsBundle(nullptr, creatorUid);
    ASSERT_EQ(flag, false);

    flag = advancedNotificationService_->IsSaCreateSystemLiveViewAsBundle(record, creatorUid);
    ASSERT_EQ(flag, false);

    record->notification->GetNotificationRequest().SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    flag = advancedNotificationService_->IsSaCreateSystemLiveViewAsBundle(record, creatorUid);
    ASSERT_EQ(flag, false);
}

/**
 * @tc.name: HandleUpdateLiveViewNotificationTimer_001
 * @tc.desc: Test HandleUpdateLiveViewNotificationTimer
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, HandleUpdateLiveViewNotificationTimer_001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    int32_t TYPE_CODE_DOWNLOAD = 8;
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    localLiveViewContent->SetType(TYPE_CODE_DOWNLOAD);
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    int creatorUid = 1096;
    request->SetCreatorUid(creatorUid);
    int ownerUid = 20099999;
    request->SetOwnerUid(ownerUid);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", ownerUid);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    ASSERT_NE(record, nullptr);
    advancedNotificationService_->AddToNotificationList(record);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
}

/**
 * @tc.name: AddToDelayNotificationList_001
 * @tc.desc: Test AddToDelayNotificationList return 1
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, AddToDelayNotificationList_001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);

    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToDelayNotificationList(record);
    ASSERT_EQ(advancedNotificationService_->delayNotificationList_.size(), 1);
}

/**
 * @tc.name: OnSubscriberAdd_100
 * @tc.desc: Test OnSubscriberAdd when record is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, OnSubscriberAdd_100, Function | SmallTest | Level1)
{
    advancedNotificationService_->currentUserId.clear();
    auto ret = advancedNotificationService_->OnSubscriberAdd(nullptr, 100);

    ASSERT_EQ(ret, (int)ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: OnSubscriberAdd_200
 * @tc.desc: Test OnSubscriberAdd when notification doesn't exist
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, OnSubscriberAdd_200, Function | SmallTest | Level1)
{
    auto record = NotificationSubscriberManager::GetInstance()->CreateSubscriberRecord(nullptr);

    advancedNotificationService_->currentUserId.clear();
    auto ret = advancedNotificationService_->OnSubscriberAdd(record, 100);

    ASSERT_EQ(ret, (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: OnSubscriberAdd_300
 * @tc.desc: Test OnSubscriberAdd when notification exists
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, OnSubscriberAdd_300, Function | SmallTest | Level1)
{
    advancedNotificationService_->currentUserId.clear();
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto notificationRecord = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(notificationRecord);

    auto record = NotificationSubscriberManager::GetInstance()->CreateSubscriberRecord(nullptr);

    auto ret = advancedNotificationService_->OnSubscriberAdd(record, 100);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SetNotificationRequestToDb_100
 * @tc.desc: Test SetNotificationRequestToDb when isOnlyLocalUpdate is true
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, SetNotificationRequestToDb_100, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetIsOnlyLocalUpdate(true);
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    AdvancedNotificationService::NotificationRequestDb requestDb =
        { .request = request, .bundleOption = bundle};

    auto ret = advancedNotificationService_->SetNotificationRequestToDb(requestDb);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: UpdateInDelayNotificationList_100
 * @tc.desc: Test UpdateInDelayNotificationList when publish immediately
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, UpdateInDelayNotificationList_100, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetPublishDelayTime(0);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToDelayNotificationList(record);

    sptr<NotificationRequest> request1 = new (std::nothrow) NotificationRequest();
    request1->SetSlotType(slotType);
    request1->SetNotificationId(1);
    request1->SetPublishDelayTime(1000);
    auto liveContent1 = std::make_shared<NotificationLiveViewContent>();
    auto content1 = std::make_shared<NotificationContent>(liveContent1);
    request1->SetContent(content1);
    sptr<NotificationBundleOption> bundle1 = new NotificationBundleOption("test", 1);
    auto record1 = advancedNotificationService_->MakeNotificationRecord(request1, bundle1);
    advancedNotificationService_->UpdateInDelayNotificationList(record1);

    auto iter = advancedNotificationService_->delayNotificationList_.begin();
    ASSERT_EQ((*iter).first->request->GetPublishDelayTime(), 1000);
}

/**
 * @tc.name: SaPublishSystemLiveViewAsBundle_100
 * @tc.desc: Test SaPublishSystemLiveViewAsBundle when publish immediately
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, SaPublishSystemLiveViewAsBundle_100, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetPublishDelayTime(0);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto ret = advancedNotificationService_->SaPublishSystemLiveViewAsBundle(record);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SaPublishSystemLiveViewAsBundle_200
 * @tc.desc: Test SaPublishSystemLiveViewAsBundle when notification exists
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, SaPublishSystemLiveViewAsBundle_200, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetPublishDelayTime(1000);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToDelayNotificationList(record);

    auto ret = advancedNotificationService_->SaPublishSystemLiveViewAsBundle(record);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SaPublishSystemLiveViewAsBundle_300
 * @tc.desc: Test SaPublishSystemLiveViewAsBundle when notification doesn't exist
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, SaPublishSystemLiveViewAsBundle_300, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetPublishDelayTime(1000);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto ret = advancedNotificationService_->SaPublishSystemLiveViewAsBundle(record);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: IsNotificationExistsInDelayList_100
 * @tc.desc: Test IsNotificationExistsInDelayList when notification exists
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, IsNotificationExistsInDelayList_100, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToDelayNotificationList(record);
    std::string key = record->notification->GetKey();

    auto ret = advancedNotificationService_->IsNotificationExistsInDelayList(key);

    ASSERT_TRUE(ret);
}

/**
 * @tc.name: IsNotificationExistsInDelayList_200
 * @tc.desc: Test IsNotificationExistsInDelayList when notification doesn't exist
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, IsNotificationExistsInDelayList_200, Function | SmallTest | Level1)
{
    std::string key = "bunlde";

    auto ret = advancedNotificationService_->IsNotificationExistsInDelayList(key);

    ASSERT_FALSE(ret);
}

/**
 * @tc.name: StartPublishDelayedNotificationTimeOut_100
 * @tc.desc: Test StartPublishDelayedNotificationTimeOut when publish with updateOnly is true
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, StartPublishDelayedNotificationTimeOut_100, Function | SmallTest | Level1)
{
    int32_t ownerUid = 1;
    int32_t notificationId = 1;

    advancedNotificationService_->StartPublishDelayedNotificationTimeOut(ownerUid, notificationId);

    auto ret = advancedNotificationService_->GetFromDelayedNotificationList(ownerUid, notificationId);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: StartPublishDelayedNotification_100
 * @tc.desc: Test StartPublishDelayedNotification when publish with updateOnly is true
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, StartPublishDelayedNotification_100, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetUpdateOnly(true);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto ret = advancedNotificationService_->StartPublishDelayedNotification(record);

    ASSERT_EQ(ret, (int)ERR_ANS_INNER_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: StartPublishDelayedNotification_200
 * @tc.desc: Test StartPublishDelayedNotification when notificationList_ is empty
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, StartPublishDelayedNotification_200, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetAutoDeletedTime(INT64_MAX);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);

    auto ret = advancedNotificationService_->StartPublishDelayedNotification(record);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: UpdateRecordByOwner_100
 * @tc.desc: Test UpdateRecordByOwner when notificationList_ is empty
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, UpdateRecordByOwner_100, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    bool isSystem = false;

    advancedNotificationService_->UpdateRecordByOwner(record, isSystem);
    auto creatorUid = request->GetCreatorUid();
    auto notificationId = request->GetNotificationId();
    auto ret = advancedNotificationService_->GetFromNotificationList(creatorUid, notificationId);

    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: UpdateRecordByOwner_200
 * @tc.desc: Test UpdateRecordByOwner when isSystem is true and timerId is not 0
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, UpdateRecordByOwner_200, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    request->SetUpdateByOwnerAllowed(true);
    std::shared_ptr<NotificationTemplate> notiTemplate = std::make_shared<NotificationTemplate>();
    std::shared_ptr<AAFwk::WantParams> data = std::make_shared<AAFwk::WantParams>();
    data->SetParam("progressValue", AAFwk::Integer::Box(1));
    notiTemplate->SetTemplateData(data);
    request->SetTemplate(notiTemplate);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>();
    request->SetWantAgent(agent);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    record->notification->SetFinishTimer(1);
    advancedNotificationService_->AddToNotificationList(record);
    bool isSystem = true;

    advancedNotificationService_->UpdateRecordByOwner(record, isSystem);
    auto ret = record->notification->GetFinishTimer();

    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UpdateRecordByOwner_300
 * @tc.desc: Test UpdateRecordByOwner when isSystem is false and timerId is not 0
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, UpdateRecordByOwner_300, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    request->SetUpdateByOwnerAllowed(true);
    std::shared_ptr<NotificationTemplate> notiTemplate = std::make_shared<NotificationTemplate>();
    std::shared_ptr<AAFwk::WantParams> data = std::make_shared<AAFwk::WantParams>();
    data->SetParam("progressValue", AAFwk::Integer::Box(1));
    notiTemplate->SetTemplateData(data);
    request->SetTemplate(notiTemplate);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>();
    request->SetWantAgent(agent);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    record->notification->SetFinishTimer(1);
    advancedNotificationService_->AddToNotificationList(record);
    bool isSystem = false;

    advancedNotificationService_->UpdateRecordByOwner(record, isSystem);
    auto ret = record->notification->GetFinishTimer();

    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: StartFinishTimerForUpdate_100
 * @tc.desc: Test StartFinishTimerForUpdate when process is FINISH_PER
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, StartFinishTimerForUpdate_100, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    uint64_t process = NotificationConstant::FINISH_PER;

    advancedNotificationService_->StartFinishTimerForUpdate(record, process);

    ASSERT_EQ(record->finish_status, AdvancedNotificationService::UploadStatus::FINISH);
}

/**
 * @tc.name: StartFinishTimerForUpdate_200
 * @tc.desc: Test StartFinishTimerForUpdate when process is not FINISH_PER
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, StartFinishTimerForUpdate_200, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    uint64_t process = NotificationConstant::DEFAULT_FINISH_STATUS;

    advancedNotificationService_->StartFinishTimerForUpdate(record, process);

    ASSERT_EQ(record->finish_status, AdvancedNotificationService::UploadStatus::CONTINUOUS_UPDATE_TIME_OUT);
}

/**
 * @tc.name: SetFinishTimerForCommonLiveView_100
 * @tc.desc: Test SetFinishTimer
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, SetFinishTimerForCommonLiveView_100, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    record->request->SetAutoDeletedTime(100);
    ErrCode res = advancedNotificationService_->SetFinishTimer(record);
    EXPECT_EQ(res, ERR_OK);
}


/**
 * @tc.name: SetRemoveOnProcessExitState_00001
 * @tc.desc: Test SetRemoveOnProcessExitState toggle
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, SetRemoveOnProcessExitState_00001, Function | SmallTest | Level1)
{
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_INVAILD);
    EXPECT_EQ(liveViewContent->GetRemoveOnProcessExitState(),
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_INVAILD);
}

/**
 * @tc.name: GetRemoveOnProcessExitState_00001
 * @tc.desc: Test GetRemoveOnProcessExitState default value
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, GetRemoveOnProcessExitState_00001, Function | SmallTest | Level1)
{
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto defaultValue = liveViewContent->GetRemoveOnProcessExitState();
    EXPECT_EQ(defaultValue, NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_INVAILD);
}

/**
 * @tc.name: IncrementalUpdateLiveview_00001
 * @tc.desc: Test IncrementalUpdateLiveview with valid old request, isOnlyLocalUpdate different
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, IncrementalUpdateLiveview_00001, Function | SmallTest | Level1)
{
    auto oldRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    oldRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    oldLiveViewContent->SetIsOnlyLocalUpdate(true);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveViewContent);
    oldRequest->SetContent(oldContent);

    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetIsOnlyLocalUpdate(false);
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);

    newRequest->IncrementalUpdateLiveview(oldRequest);

    auto updatedContent = newRequest->GetContent();
    ASSERT_NE(updatedContent, nullptr);
    auto updatedLiveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(
        updatedContent->GetNotificationContent());
    ASSERT_NE(updatedLiveViewContent, nullptr);
    EXPECT_EQ(updatedLiveViewContent->GetIsOnlyLocalUpdate(), true);
}

/**
 * @tc.name: IncrementalUpdateLiveview_00002
 * @tc.desc: Test IncrementalUpdateLiveview with valid old request, isOnlyLocalUpdate different
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, IncrementalUpdateLiveview_00002, Function | SmallTest | Level1)
{
    auto oldRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    oldRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto oldLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    oldLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto oldContent = std::make_shared<NotificationContent>(oldLiveViewContent);
    oldRequest->SetContent(oldContent);

    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_INVAILD);
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);

    newRequest->IncrementalUpdateLiveview(oldRequest);

    auto updatedContent = newRequest->GetContent();
    ASSERT_NE(updatedContent, nullptr);
    auto updatedLiveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(
        updatedContent->GetNotificationContent());
    ASSERT_NE(updatedLiveViewContent, nullptr);
    EXPECT_EQ(updatedLiveViewContent->GetRemoveOnProcessExitState(),
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
}

/**
 * @tc.name: AddAppObserverSet_00001
 * @tc.desc: Test AddAppObserverSet
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, AddAppObserverSet_00001, Function | SmallTest | Level1)
{
    auto service = AdvancedNotificationService::GetInstance();
    ASSERT_NE(service, nullptr);
    service->AddAppObserver(nullptr);
}

/**
 * @tc.name: AddAppObserverSet_00002
 * @tc.desc: Test AddAppObserverSet
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, AddAppObserverSet_00002, Function | SmallTest | Level1)
{
    auto service = AdvancedNotificationService::GetInstance();
    ASSERT_NE(service, nullptr);
    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    service->AddAppObserver(newRequest);
}

/**
 * @tc.name: AddAppObserverSet_00003
 * @tc.desc: Test AddAppObserverSet
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, AddAppObserverSet_00003, Function | SmallTest | Level1)
{
    auto service = AdvancedNotificationService::GetInstance();
    ASSERT_NE(service, nullptr);
    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_INVAILD);
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);
    service->AddAppObserver(newRequest);
}

/**
 * @tc.name: AddAppObserverSet_00004
 * @tc.desc: Test AddAppObserverSet
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, AddAppObserverSet_00004, Function | SmallTest | Level1)
{
    auto service = AdvancedNotificationService::GetInstance();
    ASSERT_NE(service, nullptr);
    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_INVAILD);
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);
    service->AddAppObserver(newRequest);
    service->RemoveAppObserver(5);
}

/**
 * @tc.name: AddAppObserverSet_00005
 * @tc.desc: Test AddAppObserverSet
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, AddAppObserverSet_00005, Function | SmallTest | Level1)
{
    auto service = AdvancedNotificationService::GetInstance();
    ASSERT_NE(service, nullptr);
    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    newRequest->SetCreatorPid(5);
    newRequest->SetOwnerBundleName("xc");
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);
    service->AddAppObserver(newRequest);
    service->IsExistsPidInObservers(5);
    service->RemoveAppObserver(5);
    service->IsExistsPidInObservers(5);
}

/**
 * @tc.name: AddAppObserverSet_00006
 * @tc.desc: Test AddAppObserverSet
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, AddAppObserverSet_00006, Function | SmallTest | Level1)
{
    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    ASSERT_NE(newRequest, nullptr);
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    newRequest->SetCreatorPid(100);
    newRequest->SetOwnerBundleName("xc");
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);

    auto notificationAppObserver = sptr<NotificationAppStateObserver>::MakeSptr();
    advancedNotificationService_->appObserverMap_.insert(std::make_pair(100, notificationAppObserver));
    advancedNotificationService_->AddAppObserver(newRequest);
    advancedNotificationService_->RemoveAppObserver(100);
    advancedNotificationService_->appObserverMap_.insert(std::make_pair(101, nullptr));
    advancedNotificationService_->RemoveAppObserver(101);
}

/**
 * @tc.name: OnProcessDied_00001
 * @tc.desc: Test OnProcessDied with valid process data
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, OnProcessDied_00001, Function | SmallTest | Level1)
{
    auto observer = std::make_shared<NotificationAppStateObserver>();
    ASSERT_NE(observer, nullptr);

    ProcessData processData;
    processData.bundleName = "test.bundle";
    processData.pid = 12345;
    processData.processName = "testProcess";

    observer->OnProcessDied(processData);
}

/**
 * @tc.name: RemoveCommonLiveViewNotification_00001
 * @tc.desc: Test RemoveCommonLiveViewNotification with empty notification list
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, RemoveCommonLiveViewNotification_00001, Function | SmallTest | Level1)
{
    auto service = AdvancedNotificationService::GetInstance();
    ASSERT_NE(service, nullptr);

    int32_t pid = 12345;
    service->RemoveCommonLiveViewNotification(pid);
}

/**
 * @tc.name: RemoveCommonLiveViewNotification_00002
 * @tc.desc: Test RemoveCommonLiveViewNotification multiple calls with same pid
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, RemoveCommonLiveViewNotification_00002, Function | SmallTest | Level1)
{
    auto service = AdvancedNotificationService::GetInstance();
    ASSERT_NE(service, nullptr);

    int32_t pid = 1;
    service->RemoveCommonLiveViewNotification(pid);
    service->RemoveCommonLiveViewNotification(pid);
    service->RemoveCommonLiveViewNotification(pid);
}

/**
 * @tc.name: RemoveCommonLiveViewNotification_0003
 * @tc.desc: Test RemoveCommonLiveViewNotification with non-empty list but no CommonLiveView
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, RemoveCommonLiveViewNotification_0003, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetCreatorPid(100);

    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    ASSERT_NE(liveContent, nullptr);
    auto content = std::make_shared<NotificationContent>(liveContent);
    ASSERT_NE(content, nullptr);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    ASSERT_NE(bundle, nullptr);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(record);

    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);
    advancedNotificationService_->AddAppObserver(newRequest);
    advancedNotificationService_->RemoveCommonLiveViewNotification(100);
}

/**
 * @tc.name: RemoveCommonLiveViewNotification_0004
 * @tc.desc: Test RemoveCommonLiveViewNotification with CommonLiveView but null request
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, RemoveCommonLiveViewNotification_0004, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetCreatorPid(100);

    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    ASSERT_NE(liveContent, nullptr);
    auto content = std::make_shared<NotificationContent>(liveContent);
    ASSERT_NE(content, nullptr);

    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    ASSERT_NE(bundle, nullptr);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    record->request = nullptr;
    advancedNotificationService_->AddToNotificationList(record);

    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);
    advancedNotificationService_->AddAppObserver(newRequest);
    advancedNotificationService_->RemoveCommonLiveViewNotification(100);
}

/**
 * @tc.name: RemoveCommonLiveViewNotification_0005
 * @tc.desc: Test RemoveCommonLiveViewNotification with CommonLiveView but pid not match
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, RemoveCommonLiveViewNotification_0005, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetCreatorPid(100);

    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    ASSERT_NE(liveContent, nullptr);
    liveContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    ASSERT_NE(content, nullptr);

    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    ASSERT_NE(bundle, nullptr);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(record);

    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);
    advancedNotificationService_->AddAppObserver(newRequest);
    advancedNotificationService_->RemoveCommonLiveViewNotification(200);
}

/**
 * @tc.name: RemoveCommonLiveViewNotification_0006
 * @tc.desc: Test RemoveCommonLiveViewNotification with CommonLiveView, pid matches but IsRemoveOnProcessExit false
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, RemoveCommonLiveViewNotification_0006, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetCreatorPid(100);

    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    ASSERT_NE(liveContent, nullptr);
    liveContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_INVAILD);
    auto content = std::make_shared<NotificationContent>(liveContent);
    ASSERT_NE(content, nullptr);
    request->SetContent(content);

    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    ASSERT_NE(bundle, nullptr);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(record);

    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);
    advancedNotificationService_->AddAppObserver(newRequest);
    advancedNotificationService_->RemoveCommonLiveViewNotification(100);
}

/**
 * @tc.name: RemoveCommonLiveViewNotification_0007
 * @tc.desc: Test RemoveCommonLiveViewNotification with all conditions met
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, RemoveCommonLiveViewNotification_0007, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetCreatorPid(100);

    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    ASSERT_NE(liveContent, nullptr);
    liveContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto content = std::make_shared<NotificationContent>(liveContent);
    ASSERT_NE(content, nullptr);
    request->SetContent(content);

    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    ASSERT_NE(bundle, nullptr);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(record);

    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);
    advancedNotificationService_->AddAppObserver(newRequest);
    advancedNotificationService_->RemoveCommonLiveViewNotification(100);
}

/**
 * @tc.name: RemoveCommonLiveViewNotification_0008
 * @tc.desc: Test RemoveCommonLiveViewNotification with multiple CommonLiveView, partial match
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, RemoveCommonLiveViewNotification_0008, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;

    sptr<NotificationRequest> request1 = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request1, nullptr);
    request1->SetSlotType(slotType);
    request1->SetNotificationId(1);
    request1->SetCreatorPid(100);

    auto liveContent1 = std::make_shared<NotificationLiveViewContent>();
    liveContent1->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto content1 = std::make_shared<NotificationContent>(liveContent1);
    request1->SetContent(content1);

    sptr<NotificationBundleOption> bundle1 = new NotificationBundleOption("test", 1);
    auto record1 = advancedNotificationService_->MakeNotificationRecord(request1, bundle1);
    advancedNotificationService_->AddToNotificationList(record1);

    sptr<NotificationRequest> request2 = new (std::nothrow) NotificationRequest();
    request2->SetSlotType(slotType);
    request2->SetNotificationId(2);
    request2->SetCreatorPid(200);

    auto liveContent2 = std::make_shared<NotificationLiveViewContent>();
    liveContent2->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto content2 = std::make_shared<NotificationContent>(liveContent2);
    request2->SetContent(content2);

    sptr<NotificationBundleOption> bundle2 = new NotificationBundleOption("test", 1);
    auto record2 = advancedNotificationService_->MakeNotificationRecord(request2, bundle2);
    advancedNotificationService_->AddToNotificationList(record2);

    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);
    advancedNotificationService_->AddAppObserver(newRequest);
    advancedNotificationService_->RemoveCommonLiveViewNotification(100);
}

/**
 * @tc.name: RemoveCommonLiveViewNotification_0009
 * @tc.desc: Test RemoveCommonLiveViewNotification with multiple CommonLiveView, all match
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, RemoveCommonLiveViewNotification_0009, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;

    sptr<NotificationRequest> request1 = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request1, nullptr);
    request1->SetSlotType(slotType);
    request1->SetNotificationId(1);
    request1->SetCreatorPid(100);

    auto liveContent1 = std::make_shared<NotificationLiveViewContent>();
    liveContent1->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto content1 = std::make_shared<NotificationContent>(liveContent1);
    ASSERT_NE(content1, nullptr);
    request1->SetContent(content1);

    sptr<NotificationBundleOption> bundle1 = new NotificationBundleOption("test", 1);
    auto record1 = advancedNotificationService_->MakeNotificationRecord(request1, bundle1);
    advancedNotificationService_->AddToNotificationList(record1);

    sptr<NotificationRequest> request2 = new (std::nothrow) NotificationRequest();
    request2->SetSlotType(slotType);
    request2->SetNotificationId(2);
    request2->SetCreatorPid(100);

    auto liveContent2 = std::make_shared<NotificationLiveViewContent>();
    liveContent2->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto content2 = std::make_shared<NotificationContent>(liveContent2);
    request2->SetContent(content2);

    sptr<NotificationBundleOption> bundle2 = new NotificationBundleOption("test", 1);
    auto record2 = advancedNotificationService_->MakeNotificationRecord(request2, bundle2);
    advancedNotificationService_->AddToNotificationList(record2);

    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);
    advancedNotificationService_->AddAppObserver(newRequest);
    advancedNotificationService_->RemoveCommonLiveViewNotification(100);
}

/**
 * @tc.name: RemoveCommonLiveViewNotification_00010
 * @tc.desc: Test RemoveCommonLiveViewNotification with mixed notification types
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, RemoveCommonLiveViewNotification_00010, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request1 = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request1, nullptr);
    request1->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request1->SetNotificationId(1);
    request1->SetCreatorPid(100);

    auto liveContent1 = std::make_shared<NotificationLiveViewContent>();
    liveContent1->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto content1 = std::make_shared<NotificationContent>(liveContent1);
    request1->SetContent(content1);

    sptr<NotificationBundleOption> bundle1 = new NotificationBundleOption("test", 1);
    auto record1 = advancedNotificationService_->MakeNotificationRecord(request1, bundle1);
    advancedNotificationService_->AddToNotificationList(record1);

    sptr<NotificationRequest> request2 = new (std::nothrow) NotificationRequest();
    request2->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request2->SetNotificationId(2);
    request2->SetCreatorPid(100);

    auto liveContent2 = std::make_shared<NotificationLiveViewContent>();
    auto content2 = std::make_shared<NotificationContent>(liveContent2);
    request2->SetContent(content2);

    sptr<NotificationBundleOption> bundle2 = new NotificationBundleOption("test", 1);
    ASSERT_NE(bundle2, nullptr);
    auto record2 = advancedNotificationService_->MakeNotificationRecord(request2, bundle2);
    advancedNotificationService_->AddToNotificationList(record2);

    auto newRequest = sptr<NotificationRequest>(new NotificationRequest(1));
    newRequest->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto newLiveViewContent = std::make_shared<NotificationLiveViewContent>();
    newLiveViewContent->SetRemoveOnProcessExitState(
        NotificationLiveViewContent::LiveViewRemoveStatus::LIVE_VIEW_REMOVE);
    auto newContent = std::make_shared<NotificationContent>(newLiveViewContent);
    newRequest->SetContent(newContent);
    advancedNotificationService_->AddAppObserver(newRequest);
    advancedNotificationService_->RemoveCommonLiveViewNotification(100);
}

/**
 * @tc.name: OnSubscriberAddWithSilentReplay_00001
 * @tc.desc: Test OnSubscriberAddWithSilentReplay with empty notification list
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, OnSubscriberAddWithSilentReplay_00001, Function | SmallTest | Level1)
{
    auto record = NotificationSubscriberManager::GetInstance()->CreateSubscriberRecord(nullptr);
    advancedNotificationService_->notificationList_.clear();
    auto ret = advancedNotificationService_->OnSubscriberAddWithSilentReplay(record);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OnSubscriberAddWithSilentReplay_00002
 * @tc.desc: Test OnSubscriberAddWithSilentReplay with notification in list
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, OnSubscriberAddWithSilentReplay_00002, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", 1);
    auto notificationRecord = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(notificationRecord);

    auto record = NotificationSubscriberManager::GetInstance()->CreateSubscriberRecord(nullptr);
    auto ret = advancedNotificationService_->OnSubscriberAddWithSilentReplay(record);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: RecoverLiveViewFromDb_SkipRecovery_00001
 * @tc.desc: Test RecoverLiveViewFromDb skips recovery when fail_count >= 2 and cleans data
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, RecoverLiveViewFromDb_SkipRecovery_00001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetReceiverUserId(100);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    liveContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t futureTime = curTime + 3600 * 1000;
    request->SetUpdateDeadLine(futureTime);
    request->SetFinishDeadLine(futureTime);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test_skip", 1);
    AdvancedNotificationService::NotificationRequestDb requestDb =
        { .request = request, .bundleOption = bundle };
    auto ret = advancedNotificationService_->SetNotificationRequestToDb(requestDb);
    ASSERT_EQ(ret, (int)ERR_OK);

    SetFailCountToDb(100, 2);
    advancedNotificationService_->notificationList_.clear();
    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);

    ASSERT_EQ(GetFailCountFromDb(100), 0);

    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb, 100);
    ASSERT_EQ(requestsdb.size(), 0);
}

/**
 * @tc.name: RecoverLiveViewFromDb_AllUsersSkip_00001
 * @tc.desc: Test RecoverLiveViewFromDb returns early when all users are skipped
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, RecoverLiveViewFromDb_AllUsersSkip_00001, Function | SmallTest | Level1)
{
    SetFailCountToDb(100, 2);
    advancedNotificationService_->notificationList_.clear();
    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
    ASSERT_EQ(GetFailCountFromDb(100), 0);
}

/**
 * @tc.name: RecoverLiveViewFromDb_NormalRecovery_00001
 * @tc.desc: Test RecoverLiveViewFromDb with valid live view, fail_count increments then resets
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, RecoverLiveViewFromDb_NormalRecovery_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetCreatorUid(100);
    request->SetCreatorUserId(100);
    request->SetReceiverUserId(100);
    request->SetLabel("test_normal");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t futureTime = curTime + 3600 * 1000;
    request->SetUpdateDeadLine(futureTime);
    request->SetFinishDeadLine(futureTime);
    request->SetGeofenceTriggerDeadLine(futureTime);
    std::shared_ptr<NotificationFlags> flags = std::make_shared<NotificationFlags>();
    flags->SetSoundEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetVibrationEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetLockScreenEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetBannerEnabled(NotificationConstant::FlagStatus::OPEN);
    request->SetFlags(flags);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("BundleName_normal", 100);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto result = advancedNotificationService_->SetNotificationRequestToDb(requestDbObj);
    ASSERT_EQ(result, ERR_OK);

    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);

    ASSERT_EQ(GetFailCountFromDb(100), 0);

    advancedNotificationService_->DoubleDeleteNotificationFromDb(
        request->GetKey(), request->GetSecureKey(), 100);
}

/**
 * @tc.name: RecoverLiveViewFromDb_ExpiredLiveView_00001
 * @tc.desc: Test RecoverLiveViewFromDb with expired deadline, IsCanRecoverCommon returns false
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, RecoverLiveViewFromDb_ExpiredLiveView_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetCreatorUid(100);
    request->SetCreatorUserId(100);
    request->SetReceiverUserId(100);
    request->SetLabel("test_expired");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t pastTime = curTime - 1000;
    request->SetUpdateDeadLine(pastTime);
    request->SetFinishDeadLine(pastTime);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("BundleName_expired", 100);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto result = advancedNotificationService_->SetNotificationRequestToDb(requestDbObj);
    ASSERT_EQ(result, ERR_OK);

    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);

    ASSERT_EQ(GetFailCountFromDb(100), 0);

    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb, 100);
    ASSERT_EQ(requestsdb.size(), 0);
}

/**
 * @tc.name: RecoverLiveViewFromDb_LiveViewEnd_00001
 * @tc.desc: Test RecoverLiveViewFromDb with LIVE_VIEW_END status, not recoverable
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, RecoverLiveViewFromDb_LiveViewEnd_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetCreatorUid(100);
    request->SetCreatorUserId(100);
    request->SetReceiverUserId(100);
    request->SetLabel("test_end");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("BundleName_end", 100);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto result = advancedNotificationService_->SetNotificationRequestToDb(requestDbObj);
    ASSERT_EQ(result, ERR_OK);

    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);

    ASSERT_EQ(GetFailCountFromDb(100), 0);

    advancedNotificationService_->DoubleDeleteNotificationFromDb(
        request->GetKey(), request->GetSecureKey(), 100);
}

/**
 * @tc.name: RecoverLiveViewFromDb_EmptyDb_00001
 * @tc.desc: Test RecoverLiveViewFromDb with empty DB, no crash and fail_count reset
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, RecoverLiveViewFromDb_EmptyDb_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
    ASSERT_EQ(GetFailCountFromDb(100), 0);
}

/**
 * @tc.name: RecoverLiveViewFromDb_FailCountOne_00001
 * @tc.desc: Test RecoverLiveViewFromDb with fail_count=1, allows recovery and resets
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, RecoverLiveViewFromDb_FailCountOne_00001, Function | SmallTest | Level1)
{
    SetFailCountToDb(100, 1);
    advancedNotificationService_->notificationList_.clear();
    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
    ASSERT_EQ(GetFailCountFromDb(100), 0);
}

/**
 * @tc.name: RecoverLiveViewFromDb_FailCountTwo_00001
 * @tc.desc: Test RecoverLiveViewFromDb with fail_count=2, allows recovery and resets
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, RecoverLiveViewFromDb_FailCountTwo_00001, Function | SmallTest | Level1)
{
    SetFailCountToDb(100, 2);
    advancedNotificationService_->notificationList_.clear();
    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
    ASSERT_EQ(GetFailCountFromDb(100), 0);
}

/**
 * @tc.name: ProcessRecoveryEntry_NullRequest_00001
 * @tc.desc: Test ProcessRecoveryEntry with null request
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, ProcessRecoveryEntry_NullRequest_00001, Function | SmallTest | Level1)
{
    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    AdvancedNotificationService::NotificationRequestDb requestDb =
        { .request = nullptr, .bundleOption = nullptr };
    requestsdb.push_back(requestDb);
    std::vector<std::string> keys;
    auto ret = advancedNotificationService_->ProcessRecoveryEntry(requestsdb, 0, keys, GetCurrentTime());
    ASSERT_FALSE(ret);
    ASSERT_TRUE(keys.empty());
}

/**
 * @tc.name: ProcessRecoveryEntry_Timeout_00001
 * @tc.desc: Test ProcessRecoveryEntry with elapsed time exceeding timeout, verify DB cleanup
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, ProcessRecoveryEntry_Timeout_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetCreatorUid(100);
    request->SetCreatorUserId(100);
    request->SetReceiverUserId(100);
    request->SetLabel("test_timeout");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t futureTime = curTime + 3600 * 1000;
    request->SetUpdateDeadLine(futureTime);
    request->SetFinishDeadLine(futureTime);
    request->SetGeofenceTriggerDeadLine(futureTime);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("BundleName_timeout", 100);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    ASSERT_EQ(advancedNotificationService_->SetNotificationRequestToDb(requestDbObj), (int)ERR_OK);

    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    requestsdb.push_back(requestDbObj);
    std::vector<std::string> keys;
    int64_t pastTime = GetCurrentTime() - 60 * 1000;
    auto ret = advancedNotificationService_->ProcessRecoveryEntry(requestsdb, 0, keys, pastTime);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(keys.empty());

    std::vector<AdvancedNotificationService::NotificationRequestDb> checkdb;
    advancedNotificationService_->GetBatchNotificationRequestsFromDb(checkdb, 100);
    ASSERT_EQ(checkdb.size(), 0);
}

/**
 * @tc.name: ProcessRecoveryEntry_TimeoutCleansRemaining_00001
 * @tc.desc: Test ProcessRecoveryEntry timeout deletes all remaining DB entries from the abort index.
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, ProcessRecoveryEntry_TimeoutCleansRemaining_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    auto buildRequest = [](int32_t notifId, const std::string &label) {
        sptr<NotificationRequest> request = new NotificationRequest(notifId);
        std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
        liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
        liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
        std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
        request->SetContent(content);
        request->SetCreatorUid(100);
        request->SetCreatorUserId(100);
        request->SetReceiverUserId(100);
        request->SetLabel(label);
        request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto epoch = std::chrono::system_clock::now().time_since_epoch();
        auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
        int64_t futureTime = curTime + 3600 * 1000;
        request->SetUpdateDeadLine(futureTime);
        request->SetFinishDeadLine(futureTime);
        request->SetGeofenceTriggerDeadLine(futureTime);
        return request;
    };
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("BundleName_to_clean", 100);
    AdvancedNotificationService::NotificationRequestDb db1 =
        { .request = buildRequest(1, "test_to_clean_1"), .bundleOption = bundleOption };
    AdvancedNotificationService::NotificationRequestDb db2 =
        { .request = buildRequest(2, "test_to_clean_2"), .bundleOption = bundleOption };
    ASSERT_EQ(advancedNotificationService_->SetNotificationRequestToDb(db1), (int)ERR_OK);
    ASSERT_EQ(advancedNotificationService_->SetNotificationRequestToDb(db2), (int)ERR_OK);

    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    ASSERT_EQ(advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb, 100), ERR_OK);
    ASSERT_EQ(requestsdb.size(), 2);

    std::vector<std::string> keys;
    int64_t pastTime = GetCurrentTime() - 60 * 1000;
    auto ret = advancedNotificationService_->ProcessRecoveryEntry(requestsdb, 0, keys, pastTime);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(keys.empty());

    std::vector<AdvancedNotificationService::NotificationRequestDb> checkdb;
    advancedNotificationService_->GetBatchNotificationRequestsFromDb(checkdb, 100);
    ASSERT_EQ(checkdb.size(), 0);
}

/**
 * @tc.name: ProcessRecoveryEntry_NormalEntry_00001
 * @tc.desc: Test ProcessRecoveryEntry with valid CommonLiveView request
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, ProcessRecoveryEntry_NormalEntry_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetCreatorUid(100);
    request->SetCreatorUserId(100);
    request->SetReceiverUserId(100);
    request->SetLabel("test_entry");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t futureTime = curTime + 3600 * 1000;
    request->SetUpdateDeadLine(futureTime);
    request->SetFinishDeadLine(futureTime);
    request->SetGeofenceTriggerDeadLine(futureTime);
    std::shared_ptr<NotificationFlags> flags = std::make_shared<NotificationFlags>();
    flags->SetSoundEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetVibrationEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetLockScreenEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetBannerEnabled(NotificationConstant::FlagStatus::OPEN);
    request->SetFlags(flags);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("BundleName_entry", 100);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto result = advancedNotificationService_->SetNotificationRequestToDb(requestDbObj);
    ASSERT_EQ(result, ERR_OK);
    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    requestsdb.push_back(requestDbObj);
    std::vector<std::string> keys;
    auto ret = advancedNotificationService_->ProcessRecoveryEntry(requestsdb, 0, keys, GetCurrentTime());
    ASSERT_FALSE(ret);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
    advancedNotificationService_->DoubleDeleteNotificationFromDb(
        request->GetKey(), request->GetSecureKey(), 100);
}

/**
 * @tc.name: ProcessRecoveryEntry_ExpiredEntry_00001
 * @tc.desc: Test ProcessRecoveryEntry with expired deadline
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, ProcessRecoveryEntry_ExpiredEntry_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetCreatorUid(100);
    request->SetCreatorUserId(100);
    request->SetReceiverUserId(100);
    request->SetLabel("test_exp_e");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t pastTime = curTime - 1000;
    request->SetUpdateDeadLine(pastTime);
    request->SetFinishDeadLine(pastTime);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("BundleName_exp_e", 100);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto result = advancedNotificationService_->SetNotificationRequestToDb(requestDbObj);
    ASSERT_EQ(result, ERR_OK);
    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    requestsdb.push_back(requestDbObj);
    std::vector<std::string> keys;
    auto ret = advancedNotificationService_->ProcessRecoveryEntry(requestsdb, 0, keys, GetCurrentTime());
    ASSERT_FALSE(ret);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
    std::vector<AdvancedNotificationService::NotificationRequestDb> checkdb;
    advancedNotificationService_->GetBatchNotificationRequestsFromDb(checkdb, 100);
    ASSERT_EQ(checkdb.size(), 0);
}

/**
 * @tc.name: ProcessRecoveryEntry_LiveViewEnd_00001
 * @tc.desc: Test ProcessRecoveryEntry with LIVE_VIEW_END status
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, ProcessRecoveryEntry_LiveViewEnd_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetCreatorUid(100);
    request->SetCreatorUserId(100);
    request->SetReceiverUserId(100);
    request->SetLabel("test_end_e");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("BundleName_end_e", 100);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto result = advancedNotificationService_->SetNotificationRequestToDb(requestDbObj);
    ASSERT_EQ(result, ERR_OK);
    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    requestsdb.push_back(requestDbObj);
    std::vector<std::string> keys;
    auto ret = advancedNotificationService_->ProcessRecoveryEntry(requestsdb, 0, keys, GetCurrentTime());
    ASSERT_FALSE(ret);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
    advancedNotificationService_->DoubleDeleteNotificationFromDb(
        request->GetKey(), request->GetSecureKey(), 100);
}

/**
 * @tc.name: GetRecoverFailCount_InvalidValue_00001
 * @tc.desc: Test GetRecoverFailCount with invalid value in DB
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, GetRecoverFailCount_InvalidValue_00001, Function | SmallTest | Level1)
{
    NotificationPreferences::GetInstance()->SetKvToDb("ans_recover_fail_count", "abc", 100);
    advancedNotificationService_->notificationList_.clear();
    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    ASSERT_EQ(GetFailCountFromDb(100), 0);

    NotificationPreferences::GetInstance()->SetKvToDb("ans_recover_fail_count", "-5", 100);
    advancedNotificationService_->notificationList_.clear();
    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    ASSERT_EQ(GetFailCountFromDb(100), 0);

    NotificationPreferences::GetInstance()->DeleteKvFromDb("ans_recover_fail_count", 100);
}

/**
 * @tc.name: CleanUserLiveViewData_WithData_00001
 * @tc.desc: Test CleanUserLiveViewData deletes all live view data
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, CleanUserLiveViewData_WithData_00001, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    request->SetReceiverUserId(100);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    liveContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t futureTime = curTime + 3600 * 1000;
    request->SetUpdateDeadLine(futureTime);
    request->SetFinishDeadLine(futureTime);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test_clean2", 1);
    AdvancedNotificationService::NotificationRequestDb requestDb =
        { .request = request, .bundleOption = bundle };
    auto ret = advancedNotificationService_->SetNotificationRequestToDb(requestDb);
    ASSERT_EQ(ret, (int)ERR_OK);
    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    ret = advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb, 100);
    ASSERT_EQ(requestsdb.size(), 1);
    SetFailCountToDb(100, 2);
    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    requestsdb.clear();
    advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb, 100);
    ASSERT_EQ(requestsdb.size(), 0);
}

/**
 * @tc.name: ProcessRecoveryEntry_NoContentFillFail_00001
 * @tc.desc: Test ProcessRecoveryEntry where FillNotificationRecord fails (request without content)
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, ProcessRecoveryEntry_NoContentFillFail_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetCreatorUid(100);
    request->SetCreatorUserId(100);
    request->SetReceiverUserId(100);
    request->SetLabel("test_nofill");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t futureTime = curTime + 3600 * 1000;
    request->SetUpdateDeadLine(futureTime);
    request->SetFinishDeadLine(futureTime);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("BundleName_nofill", 100);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto result = advancedNotificationService_->SetNotificationRequestToDb(requestDbObj);
    ASSERT_EQ(result, ERR_OK);
    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    requestsdb.push_back(requestDbObj);
    std::vector<std::string> keys;
    auto ret = advancedNotificationService_->ProcessRecoveryEntry(requestsdb, 0, keys, GetCurrentTime());
    ASSERT_FALSE(ret);
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
    std::vector<AdvancedNotificationService::NotificationRequestDb> checkdb;
    advancedNotificationService_->GetBatchNotificationRequestsFromDb(checkdb, 100);
    ASSERT_EQ(checkdb.size(), 0);
}

/**
 * @tc.name: ProcessRecoveryEntry_EmptyBundleName_00001
 * @tc.desc: Test ProcessRecoveryEntry with empty bundle name (skip Filter branch)
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, ProcessRecoveryEntry_EmptyBundleName_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetCreatorUid(100);
    request->SetCreatorUserId(100);
    request->SetReceiverUserId(100);
    request->SetLabel("test_emptybn");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t futureTime = curTime + 3600 * 1000;
    request->SetUpdateDeadLine(futureTime);
    request->SetFinishDeadLine(futureTime);
    request->SetGeofenceTriggerDeadLine(futureTime);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test_emptybn_ok", 100);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = bundleOption };
    auto result = advancedNotificationService_->SetNotificationRequestToDb(requestDbObj);
    ASSERT_EQ(result, ERR_OK);
    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 1);
    advancedNotificationService_->DoubleDeleteNotificationFromDb(
        request->GetKey(), request->GetSecureKey(), 100);
}

/**
 * @tc.name: StartRecoveryTimers_NonCommonLiveView_00001
 * @tc.desc: Test StartRecoveryTimers with non-CommonLiveView request (else branch)
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, StartRecoveryTimers_NonCommonLiveView_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    request->SetCreatorUid(100);
    request->SetCreatorUserId(100);
    request->SetReceiverUserId(100);
    request->SetLabel("test_nonclv");
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t futureTime = curTime + 3600 * 1000;
    request->SetAutoDeletedTime(futureTime);
    auto record = advancedNotificationService_->MakeNotificationRecord(request,
        new NotificationBundleOption("test_nonclv", 100));
    ASSERT_NE(record, nullptr);
    record->slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = new NotificationBundleOption("test_nonclv", 100) };
    advancedNotificationService_->StartRecoveryTimers(requestDbObj, record);
    ASSERT_NE(record->notification, nullptr);
    ASSERT_NE(record->slot, nullptr);
}

/**
 * @tc.name: StartRecoveryTimers_NoGeofenceTrigger_00001
 * @tc.desc: Test StartRecoveryTimers with CommonLiveView but no GeofenceTriggerDeadLine
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, StartRecoveryTimers_NoGeofenceTrigger_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    sptr<NotificationRequest> request = new NotificationRequest(1);
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = std::make_shared<NotificationLiveViewContent>();
    liveViewContent->SetLiveViewStatus(NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    liveViewContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW));
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);
    request->SetCreatorUid(100);
    request->SetCreatorUserId(100);
    request->SetReceiverUserId(100);
    request->SetLabel("test_nogeo");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto epoch = std::chrono::system_clock::now().time_since_epoch();
    auto curTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    int64_t futureTime = curTime + 3600 * 1000;
    request->SetUpdateDeadLine(futureTime);
    request->SetFinishDeadLine(futureTime);
    auto record = advancedNotificationService_->MakeNotificationRecord(request,
        new NotificationBundleOption("test_nogeo", 100));
    ASSERT_NE(record, nullptr);
    record->slot = new NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
    AdvancedNotificationService::NotificationRequestDb requestDbObj =
        { .request = request, .bundleOption = new NotificationBundleOption("test_nogeo", 100) };
    advancedNotificationService_->StartRecoveryTimers(requestDbObj, record);
    ASSERT_NE(record->notification, nullptr);
    ASSERT_NE(record->slot, nullptr);
    ASSERT_EQ(record->slot->GetAuthorizedStatus(), NotificationSlot::AuthorizedStatus::AUTHORIZED);
}

/**
 * @tc.name: CleanRemainingEntries_NullInRemaining_00001
 * @tc.desc: Test CleanRemainingRecoveryEntries with null request in remaining entries
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, CleanRemainingEntries_NullInRemaining_00001, Function | SmallTest | Level1)
{
    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    AdvancedNotificationService::NotificationRequestDb db1 =
        { .request = nullptr, .bundleOption = nullptr };
    AdvancedNotificationService::NotificationRequestDb db2 =
        { .request = new NotificationRequest(1), .bundleOption = nullptr };
    requestsdb.push_back(db1);
    requestsdb.push_back(db2);
    advancedNotificationService_->CleanRemainingRecoveryEntries(requestsdb, 0);
    ASSERT_EQ(requestsdb.size(), 2);
}

/**
 * @tc.name: GetRecoverFailCount_PartialAndNegative_00001
 * @tc.desc: Test GetRecoverFailCount with partial number and negative value
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, GetRecoverFailCount_PartialAndNegative_00001, Function | SmallTest | Level1)
{
    NotificationPreferences::GetInstance()->SetKvToDb("ans_recover_fail_count", "12abc", 100);
    advancedNotificationService_->RecoverLiveViewFromDb(100);
    SleepForFC();
    ASSERT_EQ(GetFailCountFromDb(100), 0);
    SetFailCountToDb(100, 0);
    NotificationPreferences::GetInstance()->SetKvToDb("ans_recover_fail_count", "-5", 101);
    advancedNotificationService_->RecoverLiveViewFromDb(101);
    SleepForFC();
    ASSERT_EQ(GetFailCountFromDb(101), 0);
    NotificationPreferences::GetInstance()->DeleteKvFromDb("ans_recover_fail_count", 100);
    NotificationPreferences::GetInstance()->DeleteKvFromDb("ans_recover_fail_count", 101);
}

/**
 * @tc.name: RecoverLiveViewFromDb_AllUsersPath_00001
 * @tc.desc: Test RecoverLiveViewFromDb with userId=-1 (all users path)
 * @tc.type: FUNC
 * @tc.require: issue#4214
 */
HWTEST_F(AnsLiveViewServiceTest, RecoverLiveViewFromDb_AllUsersPath_00001, Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationList_.clear();
    advancedNotificationService_->RecoverLiveViewFromDb(-1);
    SleepForFC();
    ASSERT_EQ(advancedNotificationService_->notificationList_.size(), 0);
    ASSERT_EQ(GetFailCountFromDb(100), 0);
}
}  // namespace Notification
}  // namespace OHOS
