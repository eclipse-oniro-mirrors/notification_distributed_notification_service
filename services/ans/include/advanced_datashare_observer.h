/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef NOTIFICATION_ADVANCED_DATASHAER_OBSERVER_H
#define NOTIFICATION_ADVANCED_DATASHAER_OBSERVER_H

#include "datashare_helper.h"
#include "iremote_broker.h"
#include "singleton.h"
#include "ans_const_define.h"
#include "system_ability_definition.h"
#include "uri.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {
namespace {

} // namespace

class AdvancedDatashareObserver : public Singleton<AdvancedDatashareObserver> {
    DECLARE_SINGLETON(AdvancedDatashareObserver);
public:
    /**
     * Registers an observer to DataObsMgr specified by the given Uri.
     *
     * @param uri, Indicates the path of the data to operate.
     * @param dataObserver, Indicates the IDataAbilityObserver object.
     */
    void RegisterSettingsObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);

    /**
     * Deregisters an observer used for DataObsMgr specified by the given Uri.
     *
     * @param uri, Indicates the path of the data to operate.
     * @param dataObserver, Indicates the IDataAbilityObserver object.
     */
    void UnRegisterSettingsObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);

    /**
     * Notifies the registered observers of a change to the data resource specified by Uri.
     *
     * @param uri, Indicates the path of the data to operate.
     */
    void NotifyChange(const Uri &uri);

    bool CheckIfSettingsDataReady();

private:
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
    static sptr<AdvancedDatashareObserver> instance_;
    static ffrt::mutex instanceMutex_;
    bool isDataShareReady_ = false;
};
} // namespace Notification
} // namespace OHOS
#endif // NOTIFICATION_ADVANCED_DATASHAER_OBSERVER_H
