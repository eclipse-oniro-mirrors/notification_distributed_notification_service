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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "notification_subscriber.h"
#include "picture_option.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {

class MockNotificationSubscriber : public NotificationSubscriber {
public:
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override {}
    void OnConnected() override {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override {}
    void OnDisconnected() override {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override {}
    void OnDied() override {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override {}
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override {}
    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override {}
};

class NotificationSubscriberTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetPictureOption_00001
 * @tc.desc: Test SetPictureOption with nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscriberTest, SetPictureOption_00001, Function | SmallTest | Level1)
{
    MockNotificationSubscriber subscriber;
    subscriber.SetPictureOption(nullptr);
    EXPECT_EQ(subscriber.GetPictureOption(), nullptr);
}

/**
 * @tc.name: SetPictureOption_00002
 * @tc.desc: Test SetPictureOption with valid object.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscriberTest, SetPictureOption_00002, Function | SmallTest | Level1)
{
    MockNotificationSubscriber subscriber;
    sptr<PictureOption> option = new PictureOption({"pic1", "pic2"});
    subscriber.SetPictureOption(option);
    ASSERT_NE(subscriber.GetPictureOption(), nullptr);
    EXPECT_EQ(subscriber.GetPictureOption()->GetPreparseLiveViewPicList().size(), 2u);
}

/**
 * @tc.name: SetPictureOption_00003
 * @tc.desc: Test SetPictureOption with empty list.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscriberTest, SetPictureOption_00003, Function | SmallTest | Level1)
{
    MockNotificationSubscriber subscriber;
    sptr<PictureOption> option = new PictureOption();
    subscriber.SetPictureOption(option);
    ASSERT_NE(subscriber.GetPictureOption(), nullptr);
    EXPECT_EQ(subscriber.GetPictureOption()->GetPreparseLiveViewPicList().size(), 0u);
}

/**
 * @tc.name: GetPictureOption_00001
 * @tc.desc: Test GetPictureOption after setting.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscriberTest, GetPictureOption_00001, Function | SmallTest | Level1)
{
    MockNotificationSubscriber subscriber;
    sptr<PictureOption> option = new PictureOption({"pic1"});
    subscriber.SetPictureOption(option);
    sptr<PictureOption> result = subscriber.GetPictureOption();
    EXPECT_EQ(result, option);
    EXPECT_EQ(result->GetPreparseLiveViewPicList()[0], "pic1");
}

/**
 * @tc.name: GetPictureOption_00002
 * @tc.desc: Test GetPictureOption multiple times.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscriberTest, GetPictureOption_00002, Function | SmallTest | Level1)
{
    MockNotificationSubscriber subscriber;
    sptr<PictureOption> option1 = new PictureOption({"pic1"});
    subscriber.SetPictureOption(option1);
    sptr<PictureOption> first = subscriber.GetPictureOption();
    EXPECT_EQ(first, option1);
    
    sptr<PictureOption> option2 = new PictureOption({"pic2"});
    subscriber.SetPictureOption(option2);
    sptr<PictureOption> second = subscriber.GetPictureOption();
    EXPECT_EQ(second, option2);
    EXPECT_NE(second, option1);
}

/**
 * @tc.name: PictureOption_MemoryTest_00001
 * @tc.desc: Test PictureOption pointer memory management.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationSubscriberTest, PictureOption_MemoryTest_00001, Function | SmallTest | Level1)
{
    MockNotificationSubscriber subscriber;
    {
        sptr<PictureOption> option = new PictureOption({"pic1"});
        subscriber.SetPictureOption(option);
    }
    sptr<PictureOption> result = subscriber.GetPictureOption();
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetPreparseLiveViewPicList().size(), 1u);
}

}  // namespace Notification
}  // namespace OHOS