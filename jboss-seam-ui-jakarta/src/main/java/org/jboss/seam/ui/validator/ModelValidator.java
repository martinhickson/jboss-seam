package org.jboss.seam.ui.validator;

import java.util.Set;

import jakarta.el.ELException;
import jakarta.el.ValueExpression;
import jakarta.faces.application.FacesMessage;
import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.validator.Validator;
import jakarta.faces.validator.ValidatorException;
import jakarta.validation.ConstraintViolation;

import org.jboss.seam.core.Validators;
import org.jboss.seam.faces.FacesMessages;

/**
 * Validates model using Bean Validation annotations.
 *
 * @author Gavin King
 * @author Jacob Hookom
 *
 */
public class ModelValidator implements Validator {

    @SuppressWarnings("rawtypes")
    @Override
    public void validate(FacesContext facesContext, UIComponent component, Object value) throws ValidatorException {
        ValueExpression valueExpression = component.getValueExpression("value");
        if (valueExpression != null) {
            // TODO: note that this code is duplicated to Param.getValueFromRequest()!!
            Set invalidValues;
            try {
                invalidValues = Validators.instance().validate(valueExpression, facesContext.getELContext(), value);
            } catch (ELException ele) {
                Throwable cause = ele.getCause();
                if (cause == null)
                    cause = ele;
                throw new ValidatorException(createMessage(cause), cause);
            }

            if (invalidValues != null && !invalidValues.isEmpty()) {
                throw new ValidatorException(createMessage(invalidValues, resolveLabel(facesContext, component)));
            }
        }
    }

    private FacesMessage createMessage(Set<ConstraintViolation<Object>> invalidValues, Object label) {
        String message = invalidValues.iterator().next().getMessage();
        return FacesMessages.createFacesMessage(FacesMessage.SEVERITY_ERROR, message, label);
    }

    private FacesMessage createMessage(Throwable cause) {
        return new FacesMessage(FacesMessage.SEVERITY_ERROR, "model validation failed:" + cause.getMessage(), null);
    }

    private Object resolveLabel(FacesContext facesContext, UIComponent component) {
        Object lbl = component.getAttributes().get("label");
        if (lbl == null || (lbl instanceof String && ((String) lbl).isEmpty())) {
            lbl = component.getValueExpression("label");
        }
        if (lbl == null) {
            lbl = component.getClientId(facesContext);
        }
        return lbl;
    }

}
