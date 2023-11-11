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
#include "notification_local_live_view_content.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationLocalLiveViewContentTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetTypeCode_00001
 * @tc.desc: Test SetTypeCode parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationLocalLiveViewContentTest, SetTypeCode_00001, Function | SmallTest | Level1)
{
    int32_t typeCode = 1;
    auto rrc = std::make_shared<NotificationLocalLiveViewContent>();
    rrc->SetType(typeCode);
    EXPECT_EQ(rrc->GetType(), typeCode);
}
}
}
