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

#include <memory>

#include "gtest/gtest.h"
#include "bundle_resource_helper.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class DistributedBundleHelperTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
};

void DistributedBundleHelperTest::SetUp() {}

void DistributedBundleHelperTest::TearDown() {}


/**
 * @tc.name      : DistributedBundleHelperTest_00100
 * @tc.number    : DistributedBundleHelperTest_00100
 * @tc.desc      : test GetAppIndexByUid function
 */
HWTEST_F(DistributedBundleHelperTest, DistributedServiceTest_00100, Function | SmallTest | Level1)
{
    int32_t uid = 100010;
    int32_t index = DelayedSingleton<BundleResourceHelper>::GetInstance()->GetAppIndexByUid(uid);
    ASSERT_EQ(0, index);
}
} // namespace Notification
} // namespace OHOS
