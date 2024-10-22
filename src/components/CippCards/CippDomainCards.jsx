import React, { useEffect, useState } from "react";
import {
  Grid,
  Button,
  Collapse,
  Switch,
  TextField,
  IconButton,
  Tooltip,
  Typography,
  Chip,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import ClearIcon from "@mui/icons-material/Clear";
import SettingsIcon from "@mui/icons-material/Settings";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ErrorIcon from "@mui/icons-material/Error";
import WarningIcon from "@mui/icons-material/Warning";
import HelpIcon from "@mui/icons-material/Help";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import { Controller, get, useForm } from "react-hook-form";
import { ApiGetCall } from "/src/api/ApiCall";
import CippButtonCard from "/src/components/CippCards/CippButtonCard";
import { CippCodeBlock } from "/src/components/CippComponents/CippCodeBlock";
import { CippOffCanvas } from "../CippComponents/CippOffCanvas";
import { CippPropertyListCard } from "./CippPropertyListCard";
import { getCippTranslation } from "../../utils/get-cipp-translation";
import { getCippFormatting } from "../../utils/get-cipp-formatting";

const ResultList = ({ passes = [], warns = [], fails = [] }) => (
  <ul>
    {passes.map((pass, index) => (
      <Typography key={index} sx={{ display: "flex", alignItems: "center", marginBottom: "8px" }}>
        <CheckCircleIcon style={{ color: "green", marginRight: "4px" }} />
        {pass}
      </Typography>
    ))}
    {warns.map((warn, index) => (
      <Typography key={index} sx={{ display: "flex", alignItems: "center", marginBottom: "8px" }}>
        <WarningIcon style={{ color: "orange", marginRight: "4px" }} />
        {warn}
      </Typography>
    ))}
    {fails.map((fail, index) => (
      <Typography key={index} sx={{ display: "flex", alignItems: "center", marginBottom: "8px" }}>
        <ErrorIcon style={{ color: "red", marginRight: "4px" }} />
        {fail}
      </Typography>
    ))}
  </ul>
);

// Custom MX Results Card component
const MXResultsCard = ({ domain, mxData, isFetching }) => {
  const [visible, setVisible] = useState(false);

  const handleDetailsClick = () => {
    setVisible(true);
  };

  const providerName = mxData?.MailProvider?.Name || "Unknown";
  const validationPasses = mxData?.ValidationPasses || [];
  const validationWarns = mxData?.ValidationWarns || [];
  const validationFails = mxData?.ValidationFails || [];

  const allPassed = validationFails.length === 0 && validationWarns.length === 0;

  const helpUrl = mxData?.MailProvider?._MxComment || "";
  return (
    <CippButtonCard
      title={
        <div style={{ display: "flex", alignItems: "center" }}>
          {allPassed && <CheckCircleIcon style={{ color: "green", marginRight: "8px" }} />}
          MX Records
        </div>
      }
      cardSx={{ display: "flex", flexDirection: "column", height: "100%" }}
      cardActions={
        <>
          {helpUrl && (
            <Tooltip title="Help">
              <IconButton href={helpUrl} target="_blank">
                <HelpIcon />
              </IconButton>
            </Tooltip>
          )}
          <Tooltip title="Details">
            <IconButton onClick={handleDetailsClick}>
              <MoreVertIcon />
            </IconButton>
          </Tooltip>
          <CippOffCanvas
            visible={visible}
            children={<CippCodeBlock code={JSON.stringify(mxData?.Records)} />}
            onClose={() => setVisible(false)}
          />
        </>
      }
      isFetching={isFetching}
    >
      {!isFetching && (
        <>
          <Typography variant="h6" gutterBottom>
            Mail Provider:
          </Typography>
          <Chip color="info" className="mb-2" label={`${providerName}`} />
          <ResultList passes={validationPasses} warns={validationWarns} fails={validationFails} />
        </>
      )}
    </CippButtonCard>
  );
};

// DomainResultCard to reuse for other result types
function DomainResultCard({ title, data, isFetching, info, type }) {
  const [visible, setVisible] = useState(false);

  const offCanvasData =
    //switch case for different types of data
    type === "whois"
      ? {
          extendedInfoFields: [
            "Domain Name",
            "Creation Date",
            "Updated Date",
            "Registrar Registration Expiration Date",
            "Registrar",
            "Registrar URL",
            "Registrar Abuse Contact Email",
            "Domain Status",
            "Name Server",
            "DNSSEC",
          ],
          extendedData: data,
        }
      : type === "MTA-STS"
      ? {
          children: (
            <Grid container spacing={2}>
              <Grid item xs={12}>
                {info}
              </Grid>
            </Grid>
          ),
        }
      : type === "DNSSEC"
      ? {
          children: <CippCodeBlock language="JSON" code={JSON.stringify(data)} />,
        }
      : type === "DKIM"
      ? {
          children: data?.Records?.map((record, index) => (
            <div key={index}>
              <Typography variant="h6" gutterBottom>
                Selector: {record?.Selector}
              </Typography>
              <CippCodeBlock code={record?.Record} />
              <ResultList
                passes={record?.ValidationPasses}
                warns={record?.ValidationWarns}
                fails={record?.ValidationFails}
              />
            </div>
          )),
        }
      : type === "DMARC"
      ? {
          children: (
            //4 headers, "Record" and then  <CippCodeBlock code={record?.Record} /> under it.
            <>
              <Typography variant="h6" gutterBottom>
                Record:
              </Typography>
              <CippCodeBlock code={data?.Record} />

              <CippPropertyListCard
                title="Settings"
                copyItems={true}
                propertyItems={[
                  {
                    label: "Version",
                    value: data?.Version,
                  },
                  {
                    label: "Policy",
                    value: getCippFormatting(data?.Policy, "DMARCPolicy", "text"),
                  },
                  {
                    label: "Subdomain Policy",
                    value: getCippFormatting(data?.SubdomainPolicy, "DMARCPolicy", "text"),
                  },
                  {
                    label: "Percentage",
                    value: data?.Percentage,
                  },
                  {
                    label: "SPF Alignment",
                    value: getCippFormatting(data?.SpfAlignment, "DMARCPolicy", "text"),
                  },
                  {
                    label: "Report Interval",
                    value: getCippFormatting(data?.ReportInterval, "ReportInterval", "text"),
                  },
                  {
                    label: "Report Format",
                    value: getCippFormatting(data?.ReportFormat, "DMARCPolicy", "text"),
                  },
                ]}
              />
              <CippPropertyListCard
                title="Reporting Emails"
                copyItems={true}
                propertyItems={data?.ReportingEmails.map((email) => ({
                  label: "Reporting Email(s)",
                  value: email,
                }))}
              />
              <CippPropertyListCard
                title="Forensic Emails"
                copyItems={true}
                propertyItems={data?.ForensicEmails.map((email) => ({
                  label: "Forensic Email(s)",
                  value: email,
                }))}
              />
            </>
          ),
        }
      : type === "SPF"
      ? {
          children: (
            <>
              <Typography variant="h6" gutterBottom>
                Record:
              </Typography>
              <CippCodeBlock code={data?.Record} />
              {data?.Recommendations && (
                <>
                  <CippPropertyListCard
                    title="Recommendations"
                    copyItems={true}
                    propertyItems={data?.Recommendations.map((rec) => ({
                      label: "Recommendation",
                      value: rec.Message,
                    }))}
                  />
                  
                </>
              )}

              <Typography variant="h6" gutterBottom>
                IP Addresses
              </Typography>
              <CippCodeBlock
                code={data?.RecordList.map((record) => record.IPAddresses).join("\n")}
              />
            </>
          ),
        }
      : {};

  return (
    <CippButtonCard
      title={
        <div style={{ display: "flex", alignItems: "center" }}>
          {data?.ValidationFails?.length === 0 && data?.ValidationWarns?.length === 0 && (
            <CheckCircleIcon style={{ color: "green", marginRight: "8px" }} />
          )}
          {data?.ValidationFails?.length > 0 && (
            <ErrorIcon style={{ color: "red", marginRight: "8px" }} />
          )}
          {data?.ValidationWarns?.length > 0 && (
            <WarningIcon style={{ color: "orange", marginRight: "8px" }} />
          )}
          {title}
        </div>
      }
      cardSx={{ display: "flex", flexDirection: "column", height: "100%" }}
      cardActions={
        <>
          {data?._Comment && (
            <Tooltip title="Help">
              <IconButton href={data?._Comment} target="_blank">
                <HelpIcon />
              </IconButton>
            </Tooltip>
          )}
          <Tooltip title="Details">
            <IconButton onClick={() => setVisible(true)}>
              <MoreVertIcon />
            </IconButton>
          </Tooltip>
        </>
      }
      isFetching={isFetching}
    >
      <Grid item xs={12}>
        {info}
      </Grid>
      <CippOffCanvas visible={visible} onClose={() => setVisible(false)} {...offCanvasData} />
    </CippButtonCard>
  );
}

// The main CippDomainCards component with new props
export const CippDomainCards = ({ domain: propDomain = "", fullwidth = false }) => {
  const { control, handleSubmit, watch, setValue } = useForm({
    defaultValues: {
      domain: propDomain,
      spfRecord: "",
      dkimSelector: "",
      subdomains: "",
      enableHttps: false,
    },
  });
  const [optionsVisible, setOptionsVisible] = useState(false);
  const [domain, setDomain] = useState(propDomain);
  const enableHttps = watch("enableHttps");

  useEffect(() => {
    if (propDomain) {
      setValue("domain", propDomain);
      setDomain(propDomain);
    }
  }, [propDomain, setValue]);

  const onSubmit = (values) => {
    setDomain(values.domain);
  };

  const handleClear = () => {
    setValue("domain", "");
    setValue("spfRecord", "");
    setValue("dkimSelector", "");
    setValue("subdomains", "");
  };

  // API calls with dynamic queryKey using domain
  const { data: whoisData, isFetching: whoisLoading } = ApiGetCall({
    url: "/api/ListDomainHealth",
    queryKey: `whois-${domain}`,
    data: { Domain: domain, Action: "ReadWhoisRecord" },
    waiting: !!domain,
  });

  const { data: nsData, isFetching: nsLoading } = ApiGetCall({
    url: "/api/ListDomainHealth",
    queryKey: `ns-${domain}`,
    data: { Domain: domain, Action: "ReadNSRecord" },
    waiting: !!domain,
  });

  const { data: mxData, isFetching: mxLoading } = ApiGetCall({
    url: "/api/ListDomainHealth",
    queryKey: `mx-${domain}`,
    data: { Domain: domain, Action: "ReadMxRecord" },
    waiting: !!domain,
  });

  const { data: spfData, isFetching: spfLoading } = ApiGetCall({
    url: "/api/ListDomainHealth",
    queryKey: `spf-${domain}`,
    data: { Domain: domain, Action: "ReadSPFRecord" },
    waiting: !!domain,
  });

  const { data: dmarcData, isFetching: dmarcLoading } = ApiGetCall({
    url: "/api/ListDomainHealth",
    queryKey: `dmarc-${domain}`,
    data: { Domain: domain, Action: "ReadDmarcPolicy" },
    waiting: !!domain,
  });

  const { data: dkimData, isFetching: dkimLoading } = ApiGetCall({
    url: "/api/ListDomainHealth",
    queryKey: `dkim-${domain}`,
    data: { Domain: domain, Action: "ReadDkimRecord" },
    waiting: !!domain,
  });

  const { data: dnssecData, isFetching: dnssecLoading } = ApiGetCall({
    url: "/api/ListDomainHealth",
    queryKey: `dnssec-${domain}`,
    data: { Domain: domain, Action: "TestDNSSEC" },
    waiting: !!domain,
  });

  const { data: mtastsData, isFetching: mtastsLoading } = ApiGetCall({
    url: "/api/ListDomainHealth",
    queryKey: `mtasts-${domain}`,
    data: { Domain: domain, Action: "TestMtaSts" },
    waiting: !!domain,
  });

  // Adjust grid item size based on fullwidth prop
  const gridItemSize = fullwidth ? 12 : 4;

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <Grid container spacing={3}>
        <Grid item xs={fullwidth ? 12 : 4}>
          <CippButtonCard
            title="Domain Check"
            cardSx={{ display: "flex", flexDirection: "column", height: "100%" }}
            cardActions={
              <Tooltip title="Settings">
                <IconButton onClick={() => setOptionsVisible(!optionsVisible)}>
                  <SettingsIcon />
                </IconButton>
              </Tooltip>
            }
          >
            <Grid container spacing={2}>
              <Grid item xs={8}>
                <Controller
                  name="domain"
                  control={control}
                  render={({ field }) => (
                    <TextField {...field} fullWidth placeholder="Domain Name" />
                  )}
                />
              </Grid>
              <Grid item xs={4}>
                <Button type="submit" variant="contained" startIcon={<SearchIcon />}>
                  Check
                </Button>
              </Grid>
            </Grid>
            <Collapse in={optionsVisible}>
              <Controller
                name="spfRecord"
                control={control}
                render={({ field }) => (
                  <TextField {...field} fullWidth label="SPF Record" className="mt-2" />
                )}
              />
              <Controller
                name="dkimSelector"
                control={control}
                render={({ field }) => (
                  <TextField {...field} fullWidth label="DKIM Selector" className="mt-2" />
                )}
              />
              <Controller
                name="enableHttps"
                control={control}
                render={({ field }) => (
                  <Switch {...field} checked={field.value} label="Enable HTTPS check" />
                )}
              />
              {enableHttps && (
                <Controller
                  name="subdomains"
                  control={control}
                  render={({ field }) => (
                    <TextField {...field} fullWidth label="HTTPS Subdomains" className="mt-2" />
                  )}
                />
              )}
              <Button
                variant="outlined"
                color="error"
                startIcon={<ClearIcon />}
                onClick={handleClear}
                className="mt-2"
              >
                Clear
              </Button>
            </Collapse>
          </CippButtonCard>
        </Grid>

        {domain && (
          <>
            <Grid item xs={12} md={gridItemSize}>
              <DomainResultCard
                title="Whois Results"
                type="whois"
                data={whoisData}
                isFetching={whoisLoading}
                info={
                  <div>
                    <p>Registrar: {whoisData?.Registrar}</p>
                  </div>
                }
              />
            </Grid>
            <Grid item xs={12} md={gridItemSize}>
              <DomainResultCard
                title="NS Records"
                data={nsData}
                isFetching={nsLoading}
                info={
                  <div>
                    <p>Nameservers:</p>
                    <pre>{nsData?.Records.join("\n")}</pre>
                  </div>
                }
              />
            </Grid>
            <Grid item xs={12} md={gridItemSize}>
              <MXResultsCard domain={domain} mxData={mxData} isFetching={mxLoading} />
            </Grid>
            <Grid item xs={12} md={gridItemSize}>
              <DomainResultCard
                title="SPF Record"
                type="SPF"
                data={spfData}
                isFetching={spfLoading}
                info={
                  <>
                    <p>SPF Record:</p>
                    <CippCodeBlock code={spfData?.Record} />
                    <ResultList
                      passes={spfData?.ValidationPasses}
                      warns={spfData?.ValidationWarns}
                      fails={spfData?.ValidationFails}
                    />
                  </>
                }
              />
            </Grid>
            <Grid item xs={12} md={gridItemSize}>
              <DomainResultCard
                title="DMARC Policy"
                type="DMARC"
                data={dmarcData}
                isFetching={dmarcLoading}
                info={
                  <div>
                    <p>DMARC Policy:</p>
                    <CippCodeBlock code={dmarcData?.Record} />
                    <ResultList
                      passes={dmarcData?.ValidationPasses}
                      warns={dmarcData?.ValidationWarns}
                      fails={dmarcData?.ValidationFails}
                    />
                  </div>
                }
              />
            </Grid>
            <Grid item xs={12} md={gridItemSize}>
              <DomainResultCard
                title="DKIM Record"
                data={dkimData}
                type={"DKIM"}
                isFetching={dkimLoading}
                info={
                  <div>
                    <p>DKIM Record:</p>
                    <CippCodeBlock code={dkimData?.Records?.[0]?.Record} />
                    <ResultList
                      passes={dkimData?.ValidationPasses}
                      warns={dkimData?.ValidationWarns}
                      fails={dkimData?.ValidationFails}
                    />
                  </div>
                }
              />
            </Grid>
            <Grid item xs={12} md={gridItemSize}>
              <DomainResultCard
                title="DNSSEC"
                type={"DNSSEC"}
                data={dnssecData}
                isFetching={dnssecLoading}
                info={
                  <div>
                    <ResultList
                      passes={dnssecData?.ValidationPasses}
                      warns={dnssecData?.ValidationWarns}
                      fails={dnssecData?.ValidationFails}
                    />
                  </div>
                }
              />
            </Grid>
            <Grid item xs={12} md={gridItemSize}>
              <DomainResultCard
                title="MTA-STS"
                type="MTA-STS"
                data={mtastsData}
                isFetching={mtastsLoading}
                info={
                  <div>
                    <p>MTA-STS Mode:</p>
                    <CippCodeBlock code={mtastsData?.StsPolicy?.Mode || "No record found"} />
                    <ResultList
                      passes={mtastsData?.ValidationPasses}
                      warns={mtastsData?.ValidationWarns}
                      fails={mtastsData?.ValidationFails}
                    />
                  </div>
                }
              />
            </Grid>
          </>
        )}
      </Grid>
    </form>
  );
};