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

#ifndef INFRASTRUCTURE_TEST_UNITTEST_MOCK_INCLUDE_MOCK_BUNDLE_SERVICE_CONNECTOR_H
#define INFRASTRUCTURE_TEST_UNITTEST_MOCK_INCLUDE_MOCK_BUNDLE_SERVICE_CONNECTOR_H

#include "gmock/gmock.h"
#include <memory>

#include "bundle_service_connector.h"

namespace OHOS {
namespace Notification {
namespace Infra {
class MockBundleServiceConnector : public IBundleServiceConnector {
public:
    MOCK_METHOD(sptr<AppExecFwk::IBundleMgr>, GetBundleManager, (), (override));
};
} // namespace Infra
} // namespace Notification
} // namespace OHOS
#endif
