/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE/2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MOCK_NOTIFICATION_TEMPLATE_BUILDER_H
#define MOCK_NOTIFICATION_TEMPLATE_BUILDER_H

#include "mock_fuzz_object.h"
#include "mock_want_params.h"
#include "notification_template.h"

namespace OHOS {
namespace Notification {

template <>
NotificationTemplate* ObjectBuilder<NotificationTemplate>::Build(FuzzedDataProvider *fdp)
{
    NotificationTemplate* templateObject = new NotificationTemplate();
    templateObject->SetTemplateName(fdp->ConsumeRandomLengthString());
    templateObject->SetTemplateData(ObjectBuilder<AAFwk::WantParams>::BuildSharedPtr(fdp));
    ANS_LOGE("Build mock veriables");
    return templateObject;
}

}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_TEMPLATE_BUILDER_H
