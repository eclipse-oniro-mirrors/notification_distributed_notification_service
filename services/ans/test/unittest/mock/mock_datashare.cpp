/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "datashare_helper.h"
#include "mock_datashare.h"

namespace OHOS {
namespace Notification {
namespace {
std::string g_getStringValue = "";
int g_goToFirstRow = DataShare::E_OK;
bool g_isFailedToCreateDataShareHelper = false;
bool g_isFailedToQueryDataShareResultSet = false;
}

void MockIsFailedGoToFirstRow(const int goToFirstRow)
{
    g_goToFirstRow = goToFirstRow;
}

void MockGetStringValue(const std::string& getStringValue)
{
    g_getStringValue = getStringValue;
}

void MockIsFailedToCreateDataShareHelper(const bool isFailed)
{
    g_isFailedToCreateDataShareHelper = isFailed;
}

void MockIsFailedToQueryDataShareResultSet(const bool isFailed)
{
    g_isFailedToQueryDataShareResultSet = isFailed;
}

} // namespace Notification

namespace DataShare {
class MockDataShareResultSet : public DataShareResultSet {
public:
    int GoToFirstRow() override
    {
        return Notification::g_goToFirstRow;
    }

    int GetColumnIndex(const std::string &columnName, int &columnIndex) override
    {
        return 0;
    }

    int GetString(int columnIndex, std::string &value) override
    {
        value = Notification::g_getStringValue;
        return 0;
    }

    int Close() override
    {
        return 0;
    }

    int GetColumnCount(int &count) override
    {
        return 0;
    }

    int GetColumnName(int columnIndex, std::string &columnName) override
    {
        return 0;
    }

    int GetRowIndex(int &position) const override
    {
        return 0;
    }

    int GoTo(int offset) override
    {
        return 0;
    }

    int GoToLastRow() override
    {
        return 0;
    }

    int GoToNextRow() override
    {
        return 0;
    }

    int GoToPreviousRow() override
    {
        return 0;
    }

    int IsEnded(bool &result) override
    {
        return 0;
    }

    int IsStarted(bool &result) const override
    {
        return 0;
    }

    int IsAtFirstRow(bool &result) const override
    {
        return 0;
    }

    int IsAtLastRow(bool &result) override
    {
        return 0;
    }

    bool IsClosed() const override
    {
        return false;
    }
};

class MockDataShareHelper : public DataShareHelper {
public:
    bool Release() override
    {
        return true;
    }

    std::vector<std::string> GetFileTypes(Uri &uri, const std::string &mimeTypeFilter) override
    {
        return {};
    }

    int OpenFile(Uri &uri, const std::string &mode) override
    {
        return 0;
    }

    int OpenRawFile(Uri &uri, const std::string &mode) override
    {
        return 0;
    }

    [[deprecated("Use InsertEx(Uri &, const DataShareValuesBucket &) instead.")]]
    int Insert(Uri &uri, const DataShareValuesBucket &value) override
    {
        return 0;
    }

    int InsertExt(Uri &uri, const DataShareValuesBucket &value, std::string &result) override
    {
        return 0;
    }

    [[deprecated("Use UpdateEx(Uri &, const DataSharePredicates &, const DataShareValuesBucket &) instead.")]]
    int Update(Uri &uri, const DataSharePredicates &predicates, const DataShareValuesBucket &value) override
    {
        return 0;
    }

    int BatchUpdate(const UpdateOperations &operations, std::vector<BatchUpdateResult> &results) override
    {
        return 0;
    }

    [[deprecated("Use DeleteEx(Uri &, const DataSharePredicates &) instead.")]]
    int Delete(Uri &uri, const DataSharePredicates &predicates) override
    {
        return 0;
    }

    std::shared_ptr<DataShareResultSet> Query(Uri &uri, const DataSharePredicates &predicates,
        std::vector<std::string> &columns, DatashareBusinessError *businessError = nullptr) override
    {
        return Notification::g_isFailedToQueryDataShareResultSet ? nullptr : std::make_shared<MockDataShareResultSet>();
    }

    std::string GetType(Uri &uri) override
    {
        return "";
    }

    int BatchInsert(Uri &uri, const std::vector<DataShareValuesBucket> &values) override
    {
        return 0;
    }

    int ExecuteBatch(const std::vector<OperationStatement> &statements, ExecResultSet &result) override
    {
        return 0;
    }

    int RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver) override
    {
        return 0;
    }

    int UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver) override
    {
        return 0;
    }

    void NotifyChange(const Uri &uri) override {}

    Uri NormalizeUri(Uri &uri) override
    {
        return uri;
    }

    Uri DenormalizeUri(Uri &uri) override
    {
        return uri;
    }

    int AddQueryTemplate(const std::string &uri, int64_t subscriberId, Template &tpl) override
    {
        return 0;
    }

    int DelQueryTemplate(const std::string &uri, int64_t subscriberId) override
    {
        return 0;
    }

    std::vector<OperationResult> Publish(const Data &data, const std::string &bundleName) override
    {
        return {};
    }

    Data GetPublishedData(const std::string &bundleName, int &resultCode) override
    {
        return {};
    }

    std::vector<OperationResult> SubscribeRdbData(const std::vector<std::string> &uris,
        const TemplateId &templateId, const std::function<void(const RdbChangeNode &changeNode)> &callback) override
    {
        return {};
    }

    std::vector<OperationResult> UnsubscribeRdbData(const std::vector<std::string> &uris,
        const TemplateId &templateId) override
    {
        return {};
    }

    std::vector<OperationResult> EnableRdbSubs(const std::vector<std::string> &uris,
        const TemplateId &templateId) override
    {
        return {};
    }

    std::vector<OperationResult> DisableRdbSubs(const std::vector<std::string> &uris,
        const TemplateId &templateId) override
    {
        return {};
    }

    std::vector<OperationResult> SubscribePublishedData(const std::vector<std::string> &uris,
        int64_t subscriberId, const std::function<void(const PublishedDataChangeNode &changeNode)> &callback) override
    {
        return {};
    }

    std::vector<OperationResult> UnsubscribePublishedData(const std::vector<std::string> &uris,
        int64_t subscriberId) override
    {
        return {};
    }

    std::vector<OperationResult> EnablePubSubs(const std::vector<std::string> &uris, int64_t subscriberId) override
    {
        return {};
    }

    std::vector<OperationResult> DisablePubSubs(const std::vector<std::string> &uris, int64_t subscriberId) override
    {
        return {};
    }
};

std::shared_ptr<DataShareHelper> DataShareHelper::Creator(const sptr<IRemoteObject> &token, const std::string &strUri,
    const std::string &extUri, const int waitTime, bool isSystem)
{
    return Notification::g_isFailedToCreateDataShareHelper ? nullptr : std::make_shared<MockDataShareHelper>();
}
} // namespace DataShare
} // namespace OHOS