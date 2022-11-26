/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <iostream>

#define private public
#define protected public
#include "system_event_observer.h"
#undef private
#undef protected
#include "ans_inner_errors.h"
#include "common_event_support.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class SystemEventObserverTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<SystemEventObserver> stub_;
};

void SystemEventObserverTest::SetUpTestCase()
{
}

void SystemEventObserverTest::TearDownTestCase()
{
}

void SystemEventObserverTest::SetUp()
{
    ISystemEvent iSystemEvent;
    stub_ = std::make_shared<SystemEventObserver>(iSystemEvent);
}

void SystemEventObserverTest::TearDown()
{
}

/**
 * @tc.number    : OnReceiveEvent_001
 * @tc.name      : 
 * @tc.desc      : Test OnReceiveEvent function, return is void.
 */
HWTEST_F(SystemEventObserverTest, OnReceiveEvent_001, Function | SmallTest | Level1)
{
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED));
    
    stub_->OnReceiveEvent(data);
}

/**
 * @tc.number    : OnReceiveEvent_002
 * @tc.name      : 
 * @tc.desc      : Test OnReceiveEvent function, return is void.
 */
HWTEST_F(SystemEventObserverTest, OnReceiveEvent_002, Function | SmallTest | Level1)
{
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED));
    stub_->OnReceiveEvent(data);
}

/**
 * @tc.number    : OnReceiveEvent_003
 * @tc.name      : 
 * @tc.desc      : Test OnReceiveEvent function, return is void.
 */
HWTEST_F(SystemEventObserverTest, OnReceiveEvent_003, Function | SmallTest | Level1)
{
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED));
    stub_->OnReceiveEvent(data);
}

/**
 * @tc.number    : OnReceiveEvent_004
 * @tc.name      : 
 * @tc.desc      : Test OnReceiveEvent function, return is void.
 */
HWTEST_F(SystemEventObserverTest, OnReceiveEvent_004, Function | SmallTest | Level1)
{
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED));
    stub_->OnReceiveEvent(data);
}

/**
 * @tc.number    : GetBundleOption_001
 * @tc.name      : 
 * @tc.desc      : Test GetBundleOption function.
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(SystemEventObserverTest, GetBundleOption_001, Function | SmallTest | Level1)
{
    EventFwk::Want want;
    sptr<NotificationBundleOption> systemEventObserver = stub_->GetBundleOption(want);
    EXPECT_NE(systemEventObserver, nullptr);
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(std::string(), -1);
    bundleOption ->SetBundleName("BundleName");
    bundleOption ->SetUid(2);
    stub_->GetBundleOption(want);
}
}  // namespace Notification
}  // namespace OHOS