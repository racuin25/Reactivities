import { observer } from "mobx-react-lite";
import { useStore } from "../../app/stores/store";
import { Form, Formik } from "formik";
import * as Yup from "yup";
import MyTextInput from "../../app/common/form/form/MyTextInput";
import MyTextArea from "../../app/common/form/form/MyTextArea";
import { Button } from "semantic-ui-react";

interface Props {
  setEditMode: (editMode: boolean) => void;
}

export default observer(function ProfileEditForm({ setEditMode }: Props) {
  const {
    profileStore: { profile, updateProfile },
  } = useStore();

  return (
    <Formik
      initialValues={{ displayName: profile?.displayName, bio: profile?.bio ?? "" }}
      onSubmit={(values) => {
        updateProfile(values).then(() => {
          setEditMode(false);
        });
      }}
      validationSchema={Yup.object({
        displayName: Yup.string().required(),
      })}
    >
      {({ isSubmitting, isValid, dirty }) => (
        <Form className="ui form">
          <MyTextInput placeholder="Display Name" name="displayName" />
          <MyTextArea placeholder="Add your bio" name="bio" rows={3} />
          <Button
            positive
            type="submit"
            loading={isSubmitting}
            content="Update Profile"
            floated="right"
            disabled={!isValid || !dirty}
          />
        </Form>
      )}
    </Formik>
  );
});
