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

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AnsLiveViewServiceTest::advancedNotificationService_ = nullptr;

void AnsLiveViewServiceTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    NotificationPreferences::GetInstance().ClearNotificationInRestoreFactorySettings();
    advancedNotificationService_->CancelAll();
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
    EXPECT_EQ(ret, (int)ERR_OK);

    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    ret = advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb);
    EXPECT_EQ(requestsdb.size(), 1);

    advancedNotificationService_->ProcForDeleteLiveView(record);
    requestsdb.clear();
    ret = advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb);
    EXPECT_EQ(requestsdb.size(), 0);
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
    EXPECT_EQ(ret, (int)ERR_OK);

    std::vector<AdvancedNotificationService::NotificationRequestDb> requestsdb;
    ret = advancedNotificationService_->GetBatchNotificationRequestsFromDb(requestsdb);
    EXPECT_EQ(requestsdb.size(), 0);
}

/**
 * @tc.name: GetNotificationRequestFromDb_00001
 * @tc.desc: Test GetNotificationRequestFromDb
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, GetNotificationRequestFromDb_00001, Function | SmallTest | Level1)
{
    AdvancedNotificationService::NotificationRequestDb requestsdb;
    std::string key = "ans_live_view_001";
    auto ret = advancedNotificationService_->GetNotificationRequestFromDb(key, requestsdb);
    EXPECT_NE(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetNotificationRequestFromDb_00002
 * @tc.desc: Test GetNotificationRequestFromDb
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AnsLiveViewServiceTest, GetNotificationRequestFromDb_00002, Function | SmallTest | Level1)
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    request->SetNotificationId(1);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    auto bundle = new NotificationBundleOption("test", 1);
    AdvancedNotificationService::NotificationRequestDb requestDb =
        { .request = request, .bundleOption = bundle};
    auto ret = advancedNotificationService_->SetNotificationRequestToDb(requestDb);
    EXPECT_EQ(ret, (int)ERR_OK);

    AdvancedNotificationService::NotificationRequestDb requestdbTmp;
    ret = advancedNotificationService_->GetNotificationRequestFromDb(request->GetKey(), requestdbTmp);
    EXPECT_EQ(ret, (int)ERR_OK);
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

    std::shared_ptr<PixelMap> pixelMap = std::make_shared<PixelMap>();
    const int32_t PIXEL_BYTES = 4;
    ImageInfo info;
    info.size.width = 1;
    info.size.height = 1;
    info.pixelFormat = PixelFormat::ARGB_8888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap->SetImageInfo(info);
    int32_t rowDataSize = 1 * PIXEL_BYTES;
    uint32_t bufferSize = rowDataSize * 1;
    void *buffer = malloc(bufferSize);
    if (buffer != nullptr) {
        pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    }
    oldLiveContent->SetLockScreenPicture(pixelMap);
    oldRequest->SetContent(oldContent);

    advancedNotificationService_->FillLockScreenPicture(newRequest, oldRequest);
    EXPECT_NE(newRequest->GetContent()->GetNotificationContent()->GetLockScreenPicture(), nullptr);
}

}  // namespace Notification
}  // namespace OHOS
