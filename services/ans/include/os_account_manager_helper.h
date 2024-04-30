/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "base/notification/common_event_service/services/include/os_account_manager_helper.h"
namespace OHOS {
namespace Notification {
class OsAccountManagerHelper : public DelayedSingleton<OsAccountManagerHelper> {
public:
    DISALLOW_COPY_AND_MOVE(OsAccountManagerHelper);
    
    OsAccountManagerHelper() = default;
    ~OsAccountManagerHelper() = default;

    /**
     * @brief Get OsAccountManagerHelper instance object.
     */
    static OsAccountManagerHelper &GetInstance();

    /**
     * Gets operating system account local ID from uid.
     *
     * @param uid Indicates the uid.
     * @param ids Indicates the account ID.
     * @return Returns result code.
     */
    ErrCode GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id);

    /**
     * Gets operating system account local ID from current calling.
     *
     * @param uid Indicates the uid.
     * @param ids Indicates the account ID.
     * @return Returns result code.
     */
    ErrCode GetCurrentCallingUserId(int32_t &id);
};
}
}