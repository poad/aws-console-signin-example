import StyledTextField from './styled/StyledTextField';
/* oxlint-disable react/react-in-jsx-scope */
import { TextFieldProps } from '@mui/material';

export const ReadOnlyTextField = (props: TextFieldProps) => {
  return <StyledTextField {...props} fullWidth disabled />;
};

export default ReadOnlyTextField;
