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
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "accesstoken_kit.h"
#include "notification_preferences.h"
#include "notification_constant.h"
#include "pixel_map.h"
#include "int_wrapper.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::Media;

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

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    advancedNotificationService_->CancelAll("");
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AnsLiveViewServiceTest::TearDown()
{
    delete advancedNotificationService_;
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
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
    int creatorUid = 3051;
    request->SetCreatorUid(creatorUid);
    int ownerUid = 20099999;
    request->SetOwnerUid(ownerUid);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test", ownerUid);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(record);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    auto timer = record->notification->GetFinishTimer();
    advancedNotificationService_->HandleUpdateLiveViewNotificationTimer(ownerUid, true);
    ASSERT_EQ(timer, record->notification->GetFinishTimer());
    advancedNotificationService_->HandleUpdateLiveViewNotificationTimer(ownerUid, false);
    ASSERT_NE(timer, record->notification->GetFinishTimer());
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
    auto ret = advancedNotificationService_->OnSubscriberAdd(nullptr);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: OnSubscriberAdd_200
 * @tc.desc: Test OnSubscriberAdd when notification doesn't exist
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, OnSubscriberAdd_200, Function | SmallTest | Level1)
{
    auto record = NotificationSubscriberManager::GetInstance()->CreateSubscriberRecord(nullptr);

    auto ret = advancedNotificationService_->OnSubscriberAdd(record);

    ASSERT_EQ(ret, (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: OnSubscriberAdd_300
 * @tc.desc: Test OnSubscriberAdd when notification exists
 * @tc.type: FUNC
 */
HWTEST_F(AnsLiveViewServiceTest, OnSubscriberAdd_300, Function | SmallTest | Level1)
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

    auto ret = advancedNotificationService_->OnSubscriberAdd(record);

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

    ASSERT_EQ(ret, (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
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
 * @tc.desc: Test UpdateRecordByOwner when isSystem is true and timerId is 0
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

    ASSERT_EQ(ret, 0);
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
}  // namespace Notification
}  // namespace OHOS
