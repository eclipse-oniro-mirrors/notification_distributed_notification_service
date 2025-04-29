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

#include "gtest/gtest.h"
#define private public
#include "advanced_datashare_observer.h"
#undef private
#include "advanced_aggregation_data_roaming_observer.h"
#include "system_event_observer.h"

extern void MockGetSystemAbilityManager(bool mockRet);

using namespace testing::ext;

namespace OHOS {
namespace Notification {

// Test suite
class AdvancedDatashareObserverTest : public ::testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

// Test cases
HWTEST_F(AdvancedDatashareObserverTest, SystemAbilityManagerIsNullptr, Function | SmallTest | Level1)
{
    // Arrange
    MockGetSystemAbilityManager(true);

    // Act
    auto result = AdvancedDatashareObserver::GetInstance().CreateDataShareHelper();
    sptr<AdvancedAggregationDataRoamingObserver> aggregationRoamingObserver =
        new (std::nothrow) AdvancedAggregationDataRoamingObserver();
    Uri dataEnableUri("xxxx");
    AdvancedDatashareObserver::GetInstance().RegisterSettingsObserver(dataEnableUri, aggregationRoamingObserver);
    AdvancedDatashareObserver::GetInstance().UnRegisterSettingsObserver(dataEnableUri, aggregationRoamingObserver);

    // Assert
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(AdvancedDatashareObserverTest, DataShareHelperIsCreatedSuccessfully, Function | SmallTest | Level1)
{
    // Arrange
    MockGetSystemAbilityManager(false);

    // Act
    auto result = AdvancedDatashareObserver::GetInstance().CreateDataShareHelper();
    sptr<AdvancedAggregationDataRoamingObserver> aggregationRoamingObserver =
        new (std::nothrow) AdvancedAggregationDataRoamingObserver();
    Uri dataEnableUri("xxxx");
    AdvancedDatashareObserver::GetInstance().RegisterSettingsObserver(dataEnableUri, aggregationRoamingObserver);
    AdvancedDatashareObserver::GetInstance().UnRegisterSettingsObserver(dataEnableUri, aggregationRoamingObserver);

    // Assert
    EXPECT_NE(result, nullptr);
}


// Test cases
HWTEST_F(AdvancedDatashareObserverTest, DataShareReady, Function | SmallTest | Level1) {
    // Arrange
    AdvancedDatashareObserver observer;
    observer.isDataShareReady_ = true;

    // Act
    bool result = observer.CheckIfSettingsDataReady();

    // Assert
    EXPECT_TRUE(result);
}

HWTEST_F(AdvancedDatashareObserverTest, SystemAbilityManagerNull, Function | SmallTest | Level1)
{
    // Arrange
    AdvancedDatashareObserver observer;
    observer.isDataShareReady_ = false;
    // Mock SystemAbilityManagerClient to return nullptr
    MockGetSystemAbilityManager(false);

    // Act
    bool result = observer.CheckIfSettingsDataReady();

    // Assert
    EXPECT_TRUE(result);
}

HWTEST_F(AdvancedDatashareObserverTest, DataShareHelperNotReady, Function | SmallTest | Level1)
{
    // Arrange
    AdvancedDatashareObserver observer;
    observer.isDataShareReady_ = false;
    MockGetSystemAbilityManager(true);

    // Act
    bool result = observer.CheckIfSettingsDataReady();

    // Assert
    EXPECT_FALSE(result);
}
}
}