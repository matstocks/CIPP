import { Layout as DashboardLayout } from "/src/layouts/index.js";
import { useEffect, useState } from "react";
import { ApiPostCall } from "../../../api/ApiCall";
import { CippPropertyListCard } from "/src/components/CippCards/CippPropertyListCard"; // Fixed import
import { CippDataTable } from "/src/components/CippTable/CippDataTable"; // Fixed import
import { useDialog } from "../../../hooks/use-dialog";
import {
  Box,
  Container,
  Stack,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Button,
  SvgIcon,
  Tooltip,
  Typography,
} from "@mui/material";
import { MagnifyingGlassIcon, PencilIcon, TrashIcon } from "@heroicons/react/24/outline";
import { Add, AddCircle, RemoveCircle, Sync, WarningAmber } from "@mui/icons-material";
import CippFormComponent from "../../../components/CippComponents/CippFormComponent";
import { useForm, useWatch } from "react-hook-form";
import { CippApiDialog } from "../../../components/CippComponents/CippApiDialog";
import { Grid } from "@mui/system";

const CustomAddEditRowDialog = ({ formControl, open, onClose, onSubmit, defaultValues }) => {
  const fields = useWatch({ control: formControl.control, name: "fields" });

  useEffect(() => {
    if (open) {
      console.log(defaultValues);
      formControl.reset({
        fields: defaultValues.fields || [],
      });
    }
  }, [open, defaultValues]);

  const addField = () => {
    formControl.reset({
      fields: [...fields, { name: "", value: "" }],
    });
  };

  const removeField = (index) => {
    const newFields = fields.filter((_, i) => i !== index);
    formControl.reset({ fields: newFields });
  };

  return (
    <Dialog fullWidth maxWidth="lg" open={open} onClose={onClose} width="xl">
      <DialogTitle>Add/Edit Row</DialogTitle>
      <DialogContent>
        <Stack spacing={1.5} sx={{ my: 2, width: "100%" }}>
          {Array.isArray(fields) && fields?.length > 0 && (
            <>
              {fields.map((field, index) => (
                <Stack direction="row" spacing={0.5} key={index} alignItems="center" width="100%">
                  <Box width="30%">
                    <CippFormComponent
                      type="textField"
                      name={`fields[${index}].name`}
                      formControl={formControl}
                      label="Name"
                    />
                  </Box>
                  <Box width="80%">
                    <CippFormComponent
                      type="textField"
                      name={`fields[${index}].value`}
                      formControl={formControl}
                      label="Value"
                    />
                  </Box>
                  <IconButton onClick={() => removeField(index)}>
                    <RemoveCircle />
                  </IconButton>
                </Stack>
              ))}
            </>
          )}
          <Button onClick={addField} startIcon={<AddCircle />}>
            Add Property
          </Button>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={formControl.handleSubmit(onSubmit)}>Save</Button>
      </DialogActions>
    </Dialog>
  );
};

const Page = () => {
  const pageTitle = "Table Maintenance";
  const apiUrl = "/api/ExecAzBobbyTables";
  const [tables, setTables] = useState([]);
  const [selectedTable, setSelectedTable] = useState(null);
  const [tableData, setTableData] = useState([]);
  const addTableDialog = useDialog(); // Add dialog for adding table
  const deleteTableDialog = useDialog(); // Add dialog for deleting table
  const addEditRowDialog = useDialog(); // Add dialog for adding/editing row
  const [defaultAddEditValues, setDefaultAddEditValues] = useState({});
  const formControl = useForm({
    mode: "onChange",
  });

  const addEditFormControl = useForm({
    mode: "onChange",
  });

  const tableFilter = useWatch({ control: formControl.control, name: "tableFilter" });

  const fetchTables = ApiPostCall({
    queryKey: "CippTables",
    onResult: (result) => setTables(result),
  });

  const fetchTableData = ApiPostCall({
    queryKey: "CippTableData",
    onResult: (result) => {
      setTableData(result);
    },
  });

  const handleTableSelect = (tableName) => {
    setSelectedTable(tableName);
    fetchTableData.mutate({
      url: apiUrl,
      data: {
        FunctionName: "Get-AzDataTableEntity",
        TableName: tableName,
        Parameters: { First: 1000 },
      },
    });
  };

  const handleRefresh = () => {
    if (selectedTable) {
      fetchTableData.mutate({
        url: apiUrl,
        data: {
          FunctionName: "Get-AzDataTableEntity",
          TableName: selectedTable,
          Parameters: { First: 1000 },
        },
      });
    }
  };

  const tableRowAction = ApiPostCall({
    queryKey: "CippTableRowAction",
    onResult: handleRefresh,
  });

  const handleTableRefresh = () => {
    fetchTables.mutate({ url: apiUrl, data: { FunctionName: "Get-AzDataTable", Parameters: {} } });
  };

  useEffect(() => {
    handleTableRefresh();
  }, []);

  const actionItems = tables
    .filter(
      (table) =>
        tableFilter === "" ||
        tableFilter === undefined ||
        table.toLowerCase().includes(tableFilter.toLowerCase())
    )
    .map((table) => ({
      label: `${table}`,
      customFunction: () => {
        setTableData([]);
        handleTableSelect(table);
      },
      noConfirm: true,
    }));

  const propertyItems = [
    {
      label: "",
      value: (
        <Stack direction="row" spacing={1} alignItems="center">
          <SvgIcon fontSize="small">
            <MagnifyingGlassIcon />
          </SvgIcon>
          <CippFormComponent
            type="textField"
            name="tableFilter"
            formControl={formControl}
            label="Filter"
          />
        </Stack>
      ),
    },
  ];

  const getTableFields = () => {
    if (tableData.length === 0) return [];
    const sampleRow = tableData[0];
    return Object.keys(sampleRow)
      .filter((key) => key !== "ETag" && key !== "Timestamp")
      .map((key) => ({
        name: key,
        label: key,
        type: "textField",
        required: false,
      }));
  };

  return (
    <Container maxWidth="xl" sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom>
        {pageTitle}
      </Typography>
      <Grid container spacing={2}>
        <Grid item size={3}>
          <CippPropertyListCard
            title="Tables"
            propertyItems={propertyItems}
            actionItems={actionItems.sort((a, b) => a.label.localeCompare(b.label))}
            isFetching={fetchTables.isPending}
            cardSx={{ maxHeight: "calc(100vh - 170px)", overflow: "auto" }}
            actionButton={
              <Stack direction="row" spacing={1}>
                <Tooltip title="Add Table">
                  <IconButton
                    variant="contained"
                    color="primary"
                    size="small"
                    onClick={addTableDialog.handleOpen} // Open add table dialog
                  >
                    <SvgIcon fontSize="small">
                      <Add />
                    </SvgIcon>
                  </IconButton>
                </Tooltip>
                <Tooltip title="Refresh Tables">
                  <IconButton
                    variant="contained"
                    color="primary"
                    size="small"
                    onClick={handleTableRefresh}
                  >
                    <SvgIcon fontSize="small">
                      <Sync />
                    </SvgIcon>
                  </IconButton>
                </Tooltip>
              </Stack>
            }
          />
        </Grid>
        <Grid item size={9}>
          {selectedTable && (
            <Box sx={{ width: "100%" }}>
              <CippDataTable
                title={`${selectedTable}`}
                data={tableData}
                refreshFunction={handleRefresh}
                isFetching={fetchTableData.isPending}
                cardButton={
                  <Stack direction="row" spacing={1}>
                    <Button
                      variant="contained"
                      color="primary"
                      size="small"
                      onClick={() => {
                        setDefaultAddEditValues({
                          fields: getTableFields().map((field) => ({
                            name: field?.name,
                            value: "",
                          })),
                        });
                        addEditRowDialog.handleOpen();
                      }} // Open add/edit row dialog
                      startIcon={
                        <SvgIcon fontSize="small">
                          <Add />
                        </SvgIcon>
                      }
                    >
                      Add Row
                    </Button>
                    <Button
                      variant="contained"
                      color="error"
                      size="small"
                      onClick={deleteTableDialog.handleOpen} // Open delete table dialog
                      startIcon={
                        <SvgIcon fontSize="small">
                          <TrashIcon />
                        </SvgIcon>
                      }
                    >
                      Delete Table
                    </Button>
                  </Stack>
                }
                actions={[
                  {
                    label: "Edit",
                    type: "POST",
                    icon: (
                      <SvgIcon fontSize="small">
                        <PencilIcon />
                      </SvgIcon>
                    ),
                    customFunction: (row) => {
                      setDefaultAddEditValues({
                        fields: Object.keys(row)
                          .filter((key) => key !== "ETag" && key !== "Timestamp")
                          .map((key) => ({ name: key, value: row[key] })),
                      });
                      addEditRowDialog.handleOpen();
                    },
                    noConfirm: true,
                  },
                  {
                    label: "Delete",
                    type: "POST",
                    icon: (
                      <SvgIcon fontSize="small">
                        <TrashIcon />
                      </SvgIcon>
                    ),
                    url: apiUrl,
                    data: {
                      FunctionName: "Remove-AzDataTableEntity",
                      TableName: `!${selectedTable}`,
                      Parameters: {
                        Entity: { RowKey: "RowKey", PartitionKey: "PartitionKey", ETag: "ETag" },
                      },
                    },
                    onSuccess: handleRefresh,
                    confirmText: "Do you want to delete this row?",
                  },
                ]}
              />
            </Box>
          )}
        </Grid>
      </Grid>
      <CippApiDialog
        title="Add Table"
        createDialog={addTableDialog}
        fields={[{ name: "TableName", label: "Table Name", type: "textField", required: true }]}
        api={{
          url: apiUrl,
          confirmText: "Use this form to create a new table in Azure Tables.",
          type: "POST",
          data: { FunctionName: "New-AzDataTable" },
          onSuccess: () => {
            handleTableRefresh();
          },
        }}
      />
      <CippApiDialog
        title="Delete Table"
        createDialog={deleteTableDialog}
        fields={[]}
        api={{
          url: apiUrl,
          confirmText: (
            <Stack direction="row" spacing={1}>
              <WarningAmber />
              <Typography variant="body1">
                Are you sure you want to delete this table? This is a destructive action that cannot
                be undone.
              </Typography>
            </Stack>
          ),
          type: "POST",
          data: { FunctionName: "Remove-AzDataTable", TableName: selectedTable, Parameters: {} },
          onSuccess: () => {
            setSelectedTable(null);
            setTableData([]);
            handleTableRefresh();
          },
        }}
      />
      <CustomAddEditRowDialog
        formControl={addEditFormControl}
        open={addEditRowDialog.open}
        onClose={addEditRowDialog.handleClose}
        onSubmit={(data) => {
          const payload = data.fields.reduce((acc, field) => {
            acc[field.name] = field.value;
            return acc;
          }, {});
          tableRowAction.mutate({
            url: apiUrl,
            data: {
              FunctionName: "Add-AzDataTableEntity",
              TableName: selectedTable,
              Parameters: { Entity: payload, Force: true },
            },
            onSuccess: handleRefresh,
          });
          addEditRowDialog.handleClose();
        }}
        defaultValues={defaultAddEditValues}
      />
    </Container>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;