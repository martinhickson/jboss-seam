package org.jboss.seam.core;

import static org.jboss.seam.annotations.Install.BUILT_IN;

import java.util.Set;

import org.jboss.seam.core.ClassValidator;
import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.el.EL;

import jakarta.el.ELContext;
import jakarta.el.ELException;
import jakarta.el.ELResolver;
import jakarta.el.PropertyNotFoundException;
import jakarta.el.PropertyNotWritableException;
import jakarta.el.ValueExpression;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;

/**
 * Jakarta Bean Validation-based replacement for legacy ClassValidator caching.
 */
@Name("org.jboss.seam.core.validators")
@BypassInterceptors
@Scope(ScopeType.APPLICATION)
@Install(precedence = BUILT_IN)
public class Validators {

    private final ValidatorFactory factory = Validation.buildDefaultValidatorFactory();

    private final Validator validator = factory.getValidator();

    /**
     * Validate the given object.
     */
    public <T> Set<ConstraintViolation<T>> validate(T model) {
        return validator.validate(model);
    }

    /**
     * Validate a property on the given object.
     */
    public <T> Set<ConstraintViolation<T>> validateProperty(T model, String propertyName) {
        return validator.validateProperty(model, propertyName);
    }

    /**
     * Validate that the given value can be assigned to the property referred to by the ValueExpression.
     */
    public Set<?> validate(ValueExpression valueExpression, ELContext elContext, Object value) {
        ValidatingResolver validatingResolver = new ValidatingResolver(elContext.getELResolver());
        ELContext decoratedContext = EL.createELContext(elContext, validatingResolver);
        valueExpression.setValue(decoratedContext, value);
        return validatingResolver.getViolations();
    }

    class ValidatingResolver extends ELResolver {

        private final ELResolver delegate;
        private Set<?> violations;

        public ValidatingResolver(ELResolver delegate) {
            this.delegate = delegate;
        }

        public Set<?> getViolations() {
            return violations;
        }

        @Override
        public Object getValue(ELContext context, Object base, Object property)
                throws NullPointerException, PropertyNotFoundException, ELException {
            return delegate.getValue(context, base, property);
        }

        @Override
        public void setValue(ELContext context, Object base, Object property, Object value)
                throws NullPointerException, PropertyNotFoundException, PropertyNotWritableException, ELException {
            if (base != null && property != null) {
                context.setPropertyResolved(true);
                String propertyName = property.toString();
                violations = validator.validateValue(base.getClass(), propertyName, value);
            }
        }

        @Override
        public boolean isReadOnly(ELContext context, Object base, Object property)
                throws NullPointerException, PropertyNotFoundException, ELException {
            return delegate.isReadOnly(context, base, property);
        }

        @Override
        public Class<?> getType(ELContext context, Object base, Object property)
                throws NullPointerException, PropertyNotFoundException, ELException {
            return delegate.getType(context, base, property);
        }

        @Override
        public Class<?> getCommonPropertyType(ELContext context, Object base) {
            return delegate.getCommonPropertyType(context, base);
        }
    }

    public static Validators instance() {
        if (!Contexts.isApplicationContextActive()) {
            throw new IllegalStateException("No active application scope");
        }
        return (Validators) Component.getInstance(Validators.class, ScopeType.APPLICATION);
    }

    public ClassValidator getValidator(Class modelClass) {
        return null;
    }

    public ClassValidator getValidator(Object modelClass) {
        return null;
    }
}
